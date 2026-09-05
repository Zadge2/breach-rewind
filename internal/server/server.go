// Package server exposes a local-only workspace. It is not a multi-user service.
package server

import (
	"breachrewind/internal/demo"
	"breachrewind/internal/evidence"
	"breachrewind/internal/storage"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//go:embed ui
var UI embed.FS

type Server struct {
	Store  *storage.Store
	Python string
	Host   string
	busy   chan struct{}
}

func New(store *storage.Store, python, host string) *Server {
	return &Server{store, python, host, make(chan struct{}, 1)}
}
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]string{"error": message})
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok", "version": "1.0.0", "storage": "sqlite", "scope": "loopback-only"})
	})
	mux.HandleFunc("GET /api/recordings", func(w http.ResponseWriter, r *http.Request) {
		items, err := s.Store.List()
		if err != nil {
			fail(w, 500, "Unable to read recordings")
			return
		}
		writeJSON(w, 200, items)
	})
	mux.HandleFunc("GET /api/recordings/{id}", func(w http.ResponseWriter, r *http.Request) {
		b, err := s.Store.Get(r.PathValue("id"))
		if err != nil {
			s.getError(w, err)
			return
		}
		writeJSON(w, 200, b)
	})
	mux.HandleFunc("GET /api/recordings/{id}/graph", func(w http.ResponseWriter, r *http.Request) {
		b, err := s.Store.Get(r.PathValue("id"))
		if err != nil {
			s.getError(w, err)
			return
		}
		writeJSON(w, 200, evidence.Graph(b))
	})
	mux.HandleFunc("GET /api/recordings/{id}/report", func(w http.ResponseWriter, r *http.Request) {
		b, err := s.Store.Get(r.PathValue("id"))
		if err != nil {
			s.getError(w, err)
			return
		}
		bundles := []evidence.Bundle{b}
		if id := r.URL.Query().Get("baseline"); id != "" && id != b.ID {
			base, err := s.Store.Get(id)
			if err != nil {
				s.getError(w, err)
				return
			}
			bundles = append(bundles, base)
		}
		out, err := Report(bundles)
		if err != nil {
			fail(w, 500, "Viewer assets are unavailable; rebuild the viewer")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="breach-rewind-report.html"`)
		w.Write(out)
	})
	mux.HandleFunc("GET /api/compare", func(w http.ResponseWriter, r *http.Request) {
		a, err := s.Store.Get(r.URL.Query().Get("before"))
		if err != nil {
			s.getError(w, err)
			return
		}
		b, err := s.Store.Get(r.URL.Query().Get("after"))
		if err != nil {
			s.getError(w, err)
			return
		}
		writeJSON(w, 200, evidence.Compare(a, b))
	})
	mux.HandleFunc("POST /api/import", func(w http.ResponseWriter, r *http.Request) {
		b, err := evidence.Decode(http.MaxBytesReader(w, r.Body, evidence.MaxBytes))
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		b.Redact()
		if err = b.Seal(); err != nil {
			fail(w, 400, "Invalid redacted recording")
			return
		}
		if _, err = s.Store.Get(b.ID); err == nil {
			fail(w, 409, "A recording with this ID already exists")
			return
		}
		if err = s.Store.Put(b); err != nil {
			fail(w, 500, "Unable to store recording")
			return
		}
		writeJSON(w, 201, map[string]string{"id": b.ID})
	})
	mux.HandleFunc("POST /api/demo", s.runDemo)
	assets, _ := fs.Sub(UI, "ui")
	mux.Handle("GET /", http.FileServer(http.FS(assets)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		if r.Host != s.Host {
			fail(w, 403, "Host not allowed")
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			fail(w, 403, "Cross-site access denied")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Scheme != "http" || u.Host != s.Host || u.Path != "" || u.RawQuery != "" || u.User != nil {
				fail(w, 403, "Origin not allowed")
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Header.Get("X-Rewind-Client") != "1" {
				fail(w, 403, "Missing local-client header")
				return
			}
			if r.Method == "POST" && r.Header.Get("Content-Type") != "application/json" {
				fail(w, 415, "Use application/json")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func (s *Server) getError(w http.ResponseWriter, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "Recording not found")
	} else {
		fail(w, 500, "Recording is unreadable or its integrity check failed")
	}
}
func (s *Server) runDemo(w http.ResponseWriter, r *http.Request) {
	select {
	case s.busy <- struct{}{}:
		defer func() { <-s.busy }()
	default:
		fail(w, 409, "A demonstration is already running")
		return
	}
	var req struct {
		Scenario string `json:"scenario"`
		Mode     string `json:"mode"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	d.DisallowUnknownFields()
	if d.Decode(&req) != nil {
		fail(w, 400, "Invalid demo request")
		return
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		fail(w, 400, "Trailing request data")
		return
	}
	if req.Mode != "both" && req.Mode != "vulnerable" && req.Mode != "patched" {
		fail(w, 400, "Unknown mode")
		return
	}
	found := false
	for _, name := range demo.Scenarios {
		if req.Scenario == name {
			found = true
		}
	}
	if !found {
		fail(w, 400, "Unknown scenario")
		return
	}
	modes := []string{req.Mode}
	if req.Mode == "both" {
		modes = []string{"vulnerable", "patched"}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	bundles := []evidence.Bundle{}
	for _, mode := range modes {
		b, err := demo.Run(ctx, s.Python, req.Scenario, mode)
		if err != nil {
			fail(w, 500, "Demo could not complete. Check Python 3.11+ availability and the local process environment.")
			return
		}
		bundles = append(bundles, b)
	}
	if err := s.Store.PutMany(bundles); err != nil {
		fail(w, 500, "Unable to store demonstration")
		return
	}
	ids := []string{}
	for _, b := range bundles {
		ids = append(ids, b.ID)
	}
	writeJSON(w, 201, map[string]any{"ids": ids})
}
func Serve(ctx context.Context, store *storage.Store, python, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if host != "127.0.0.1" {
		return errors.New("server must bind to 127.0.0.1; remote exposure is not supported")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	s := New(store, python, listener.Addr().String())
	httpServer := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(stop)
	}()
	fmt.Printf("BREACH REWIND http://%s\nLocal-only. No telemetry or cloud uploads. Ctrl+C to stop.\n", listener.Addr())
	err = httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
