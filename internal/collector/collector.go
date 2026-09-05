// Package collector ingests native and Tracee JSON lines without executing input.
package collector

import (
	"breachrewind/internal/evidence"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type traceeEvent struct {
	Timestamp   json.Number `json:"timestamp"`
	EventName   string      `json:"eventName"`
	ProcessID   int         `json:"processId"`
	ParentID    int         `json:"parentProcessId"`
	ProcessName string      `json:"processName"`
	HostName    string      `json:"hostName"`
	ContainerID string      `json:"containerId"`
	ReturnValue int         `json:"returnValue"`
	Args        []struct {
		Name  string `json:"name"`
		Value any    `json:"value"`
	} `json:"args"`
}

func Read(r io.Reader, format, title string) (evidence.Bundle, error) {
	b := evidence.New(title, format)
	if format != "native" && format != "tracee" {
		return b, errors.New("format must be native or tracee")
	}
	limited := &io.LimitedReader{R: r, N: evidence.MaxBytes + 1}
	scan := bufio.NewScanner(limited)
	scan.Buffer(make([]byte, 4096), 128<<10)
	line := 0
	for scan.Scan() {
		line++
		data := bytes.TrimSpace(scan.Bytes())
		if len(data) == 0 {
			continue
		}
		if err := evidence.CheckJSON(data); err != nil {
			return b, fmt.Errorf("line %d: %w", line, err)
		}
		if len(b.Events) >= evidence.MaxEvents {
			return b, errors.New("too many events")
		}
		var e evidence.Event
		var err error
		if format == "native" {
			d := json.NewDecoder(bytes.NewReader(data))
			d.DisallowUnknownFields()
			err = d.Decode(&e)
			if err == nil {
				var extra any
				if d.Decode(&extra) != io.EOF {
					err = errors.New("trailing JSON")
				}
			}
		} else {
			e, err = convert(data, len(b.Events))
		}
		if err != nil {
			return b, fmt.Errorf("line %d: %w", line, err)
		}
		b.Events = append(b.Events, e)
	}
	if err := scan.Err(); err != nil {
		return b, fmt.Errorf("invalid JSONL stream: %w", err)
	}
	if limited.N <= 0 {
		return b, errors.New("input exceeds 16 MiB")
	}
	if len(b.Events) == 0 {
		return b, errors.New("no events captured")
	}
	b.Notes = append(b.Notes, "Capture is bounded to 16 MiB / 20,000 events. Input is evidence, never executable code.")
	if format == "tracee" {
		b.Notes = append(b.Notes, "Tracee JSON adapter: processId/parentProcessId/eventName/args format. PID-based links are inferred and may cross PID reuse. Syscalls are not complete request-level causality.")
	}
	b.Redact()
	return b, b.Seal()
}
func convert(data []byte, n int) (evidence.Event, error) {
	var t traceeEvent
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&t); err != nil {
		return evidence.Event{}, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return evidence.Event{}, errors.New("trailing JSON")
	}
	if t.EventName == "" || t.Timestamp == "" {
		return evidence.Event{}, errors.New("missing Tracee eventName/timestamp")
	}
	// Tracee timestamps are epoch nanoseconds; decimal epoch seconds also supported.
	var ts time.Time
	s := t.Timestamp.String()
	if strings.Contains(s, ".") {
		parts := strings.SplitN(s, ".", 2)
		sec, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return evidence.Event{}, err
		}
		fraction := parts[1]
		if len(fraction) > 9 {
			fraction = fraction[:9]
		}
		ns, err := strconv.ParseInt(fraction+strings.Repeat("0", 9-len(fraction)), 10, 64)
		if err != nil {
			return evidence.Event{}, err
		}
		ts = time.Unix(sec, ns)
	} else {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return evidence.Event{}, err
		}
		if v > 1000000000000000 {
			ts = time.Unix(0, v)
		} else {
			ts = time.Unix(v, 0)
		}
	}
	e := evidence.Event{ID: fmt.Sprintf("tracee-%06d", n+1), Time: ts.UTC(), Kind: "other", Summary: t.EventName, Severity: "info", Outcome: "observed", Source: "tracee", PID: t.ProcessID, PPID: t.ParentID, Process: t.ProcessName, Host: t.HostName, Container: t.ContainerID, Attributes: map[string]string{"operation": t.EventName, "return_value": strconv.Itoa(t.ReturnValue)}}
	switch {
	case strings.Contains(t.EventName, "exec") || strings.Contains(t.EventName, "fork") || strings.Contains(t.EventName, "exit"):
		e.Kind = "process"
	case strings.Contains(t.EventName, "open") || strings.Contains(t.EventName, "file") || strings.Contains(t.EventName, "unlink"):
		e.Kind = "file"
	case strings.Contains(t.EventName, "connect") || strings.HasPrefix(t.EventName, "net_") || strings.Contains(t.EventName, "socket"):
		e.Kind = "network"
	}
	if t.ReturnValue < 0 {
		e.Outcome = "failed"
	}
	for _, a := range t.Args {
		v, err := json.Marshal(a.Value)
		if err != nil {
			return e, err
		}
		str, ok := a.Value.(string)
		if !ok {
			str = string(v)
		}
		e.Attributes[a.Name] = str
		if a.Name == "pathname" || a.Name == "file_path" {
			e.Attributes["path"] = str
		}
	}
	return e, nil
}
