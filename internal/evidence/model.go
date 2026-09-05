// Package evidence defines the versioned, bounded and portable recording format.
package evidence

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

const Version = "1.0"
const MaxBytes = 16 << 20
const MaxEvents = 20000

type Event struct {
	ID         string            `json:"id"`
	Time       time.Time         `json:"time"`
	Kind       string            `json:"kind"`
	Summary    string            `json:"summary"`
	Severity   string            `json:"severity"`
	Outcome    string            `json:"outcome"`
	Source     string            `json:"source"`
	PID        int               `json:"pid,omitempty"`
	PPID       int               `json:"ppid,omitempty"`
	Process    string            `json:"process,omitempty"`
	Host       string            `json:"host,omitempty"`
	Container  string            `json:"container,omitempty"`
	TraceID    string            `json:"trace_id,omitempty"`
	ParentID   string            `json:"parent_id,omitempty"`
	Attributes map[string]string `json:"attributes"`
}

type Bundle struct {
	Schema    string    `json:"schema"`
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Created   time.Time `json:"created"`
	Scenario  string    `json:"scenario"`
	Mode      string    `json:"mode"`
	Collector string    `json:"collector"`
	Notes     []string  `json:"notes"`
	Events    []Event   `json:"events"`
	Digest    string    `json:"digest"`
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var levels = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
var kinds = map[string]bool{"request": true, "response": true, "process": true, "file": true, "network": true, "policy": true, "other": true}
var outcomes = map[string]bool{"success": true, "blocked": true, "attempted": true, "failed": true, "observed": true}

func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func New(title, collector string) Bundle {
	return Bundle{Schema: Version, ID: NewID(), Title: title, Created: time.Now().UTC(), Collector: collector, Notes: []string{}, Events: []Event{}}
}
func Rank(level string) int { return levels[level] }

func (b Bundle) Validate() error {
	if b.Schema != Version {
		return fmt.Errorf("unsupported schema %q", b.Schema)
	}
	if !identifier.MatchString(b.ID) || b.Created.IsZero() || b.Created.Year() < 1970 || b.Created.Year() > 9999 {
		return errors.New("invalid recording identity or timestamp")
	}
	if len(b.Title) == 0 || len(b.Title) > 240 || len(b.Collector) > 128 || len(b.Scenario) > 128 || len(b.Mode) > 64 {
		return errors.New("invalid recording metadata")
	}
	if len(b.Events) > MaxEvents || len(b.Notes) > 100 {
		return errors.New("recording exceeds item limit")
	}
	if b.Events == nil || b.Notes == nil {
		return errors.New("events and notes must be arrays, not null")
	}
	for _, n := range b.Notes {
		if len(n) > 2048 {
			return errors.New("note too long")
		}
	}
	seen := make(map[string]Event, len(b.Events))
	for _, e := range b.Events {
		if e.Attributes == nil {
			return errors.New("event attributes must be an object, not null")
		}
		if !identifier.MatchString(e.ID) || e.Time.IsZero() || e.Time.Year() < 1970 || e.Time.Year() > 9999 || !kinds[e.Kind] || !outcomes[e.Outcome] {
			return fmt.Errorf("invalid event %q", e.ID)
		}
		if _, ok := levels[e.Severity]; !ok {
			return errors.New("unknown severity")
		}
		if _, ok := seen[e.ID]; ok {
			return errors.New("duplicate event identity")
		}
		if e.ParentID != "" {
			if p, ok := seen[e.ParentID]; !ok || p.Time.After(e.Time) {
				return errors.New("parent must precede child in recording and time")
			}
		}
		if len(e.Summary) > 2048 || len(e.Source) > 128 || len(e.Process) > 1024 || len(e.Host) > 256 || len(e.Container) > 256 || len(e.TraceID) > 128 || e.PID < 0 || e.PPID < 0 || len(e.Attributes) > 64 {
			return errors.New("event exceeds field limit")
		}
		for k, v := range e.Attributes {
			if len(k) > 128 || len(v) > 4096 {
				return errors.New("event attribute too long")
			}
		}
		seen[e.ID] = e
	}
	return nil
}

func (b Bundle) Checksum() string {
	b.Digest = ""
	data, _ := json.Marshal(b)
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}
func (b *Bundle) Seal() error {
	if err := b.Validate(); err != nil {
		return err
	}
	b.Digest = b.Checksum()
	return nil
}
func Decode(r io.Reader) (Bundle, error) {
	var b Bundle
	data, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return b, err
	}
	if len(data) > MaxBytes {
		return b, errors.New("recording exceeds 16 MiB")
	}
	if err = CheckJSON(data); err != nil {
		return b, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&b); err != nil {
		return b, fmt.Errorf("invalid recording JSON: %w", err)
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return b, errors.New("trailing JSON data")
	}
	if err = b.Validate(); err != nil {
		return b, err
	}
	if b.Digest == "" || b.Digest != b.Checksum() {
		return b, errors.New("recording checksum mismatch")
	}
	return b, nil
}

// Redaction is deliberately conservative. It is not a DLP guarantee; review exports.
var secretKey = regexp.MustCompile(`(?i)(password|passwd|secret|token|authorization|cookie|api.?key|private.?key|payload|body|credential)`)
var secretValue = regexp.MustCompile(`(?i)(bearer\s+[A-Za-z0-9._~+/-]+=*|gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|AKIA[A-Z0-9]{16}|BR_DECOY_[A-Za-z0-9_-]+)`)
var assignment = regexp.MustCompile(`(?i)((?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)[^\s&;,]+`)
var homePath = regexp.MustCompile(`(?i)(/home/[^/\s]+|/Users/[^/\s]+|[a-z]:[\\/]Users[\\/][^\\/\s]+)`)

func Clean(s string) string {
	s = secretValue.ReplaceAllString(s, "[REDACTED]")
	s = assignment.ReplaceAllString(s, "${1}[REDACTED]")
	return homePath.ReplaceAllString(s, "~")
}
func (b *Bundle) Redact() {
	// Preserve referential integrity when an untrusted ID itself contains a secret.
	redactedID := func(id string) string {
		if Clean(id) == id {
			return id
		}
		sum := sha256.Sum256([]byte(id))
		return "redacted-" + hex.EncodeToString(sum[:16])
	}
	b.ID = redactedID(b.ID)
	for i := range b.Events {
		b.Events[i].ID = redactedID(b.Events[i].ID)
		b.Events[i].ParentID = redactedID(b.Events[i].ParentID)
		b.Events[i].TraceID = Clean(b.Events[i].TraceID)
	}
	b.Title = Clean(b.Title)
	b.Collector = Clean(b.Collector)
	b.Scenario = Clean(b.Scenario)
	b.Mode = Clean(b.Mode)
	for i := range b.Notes {
		b.Notes[i] = Clean(b.Notes[i])
	}
	for i := range b.Events {
		e := &b.Events[i]
		e.Summary = Clean(e.Summary)
		e.Process = Clean(e.Process)
		e.Host = Clean(e.Host)
		e.Container = Clean(e.Container)
		e.Source = Clean(e.Source)
		clean := map[string]string{}
		for k, v := range e.Attributes {
			if secretKey.MatchString(k) {
				v = "[REDACTED]"
			} else {
				v = Clean(v)
			}
			clean[Clean(k)] = v
		}
		e.Attributes = clean
	}
}

type Edge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Confidence string `json:"confidence"`
	Reason     string `json:"reason"`
}

func Graph(b Bundle) []Edge {
	edges := []Edge{}
	last := map[string]string{}
	for _, e := range b.Events {
		key := fmt.Sprintf("%s|%s|%d", e.Host, e.Container, e.PID)
		if e.ParentID != "" {
			edges = append(edges, Edge{e.ParentID, e.ID, "observed", "explicit event linkage reported by collector"})
		} else if e.PID > 0 && last[key] != "" {
			edges = append(edges, Edge{last[key], e.ID, "inferred", "same process identifier; temporal association, not proof of causality"})
		}
		if e.PID > 0 {
			last[key] = e.ID
		}
	}
	return edges
}

type Change struct {
	Signature string `json:"signature"`
	Kind      string `json:"kind"`
	Summary   string `json:"summary"`
	Before    int    `json:"before"`
	After     int    `json:"after"`
	Delta     int    `json:"delta"`
	Severity  string `json:"severity"`
}
type Comparison struct {
	Before     string   `json:"before"`
	After      string   `json:"after"`
	Changes    []Change `json:"changes"`
	Removed    int      `json:"removed"`
	Added      int      `json:"added"`
	Unchanged  int      `json:"unchanged"`
	Compatible bool     `json:"compatible"`
	Notes      []string `json:"notes"`
}

func Signature(e Event) string {
	// Explicit semantic fields intentionally exclude PIDs, timestamps and request IDs.
	keys := []string{"action", "method", "route", "path", "destination", "operation", "rule"}
	parts := []string{e.Kind, e.Outcome, e.Process}
	for _, k := range keys {
		parts = append(parts, k+"="+e.Attributes[k])
	}
	// A JSON tuple is unambiguous even when evidence contains delimiter characters.
	encoded,_:=json.Marshal(parts)
	return string(encoded)
}
func Compare(a, b Bundle) Comparison {
	c := Comparison{Before: a.ID, After: b.ID, Compatible: a.Scenario == b.Scenario && a.Collector == b.Collector, Notes: []string{"A behavior difference is not proof of a complete fix. Check workload and telemetry coverage."}, Changes: []Change{}}
	m := map[string]*Change{}
	for j, bundle := range []Bundle{a, b} {
		for _, e := range bundle.Events {
			s := Signature(e)
			if m[s] == nil {
				m[s] = &Change{Signature: s, Kind: e.Kind, Summary: e.Summary, Severity: e.Severity}
			}
			v := m[s]
			if Rank(e.Severity) > Rank(v.Severity) {
				v.Severity = e.Severity
			}
			if j == 0 {
				v.Before++
			} else {
				v.After++
			}
		}
	}
	for _, v := range m {
		v.Delta = v.After - v.Before
		if v.Delta < 0 {
			c.Removed -= v.Delta
		} else {
			c.Added += v.Delta
		}
		c.Unchanged += min(v.Before, v.After)
		c.Changes = append(c.Changes, *v)
	}
	sort.Slice(c.Changes, func(i, j int) bool {
		a, b := c.Changes[i], c.Changes[j]
		if Rank(a.Severity) != Rank(b.Severity) {
			return Rank(a.Severity) > Rank(b.Severity)
		}
		return a.Signature < b.Signature
	})
	return c
}
