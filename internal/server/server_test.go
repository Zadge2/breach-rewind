package server

import (
	"breachrewind/internal/evidence"
	"breachrewind/internal/storage"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testServer(t *testing.T) (*Server, evidence.Bundle) {
	t.Helper()
	store, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	b := evidence.New("test", "native")
	b.Seal()
	if err = store.Put(b); err != nil {
		t.Fatal(err)
	}
	return New(store, "python", "127.0.0.1:9847"), b
}
func perform(s *Server, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:9847"+path, strings.NewReader(body))
	r.Header.Set("X-Rewind-Client", "1")
	if method == "POST" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		if k == "Host" {
			r.Host = v
		} else {
			r.Header.Set(k, v)
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func TestSecurityBoundaries(t *testing.T) {
	s, _ := testServer(t)
	for name, headers := range map[string]map[string]string{"dns-rebind": {"Host": "evil.example:9847"}, "cross-origin": {"Origin": "https://evil.example"}, "opaque-origin": {"Origin": "null"}, "no-header": {"X-Rewind-Client": ""}, "cross-site": {"Sec-Fetch-Site": "cross-site"}} {
		t.Run(name, func(t *testing.T) {
			w := perform(s, "GET", "/api/recordings", "", headers)
			if w.Code != 403 {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
	w := perform(s, "GET", "/api/recordings", "", map[string]string{"Origin": "http://127.0.0.1:9847"})
	if w.Code != 200 || w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Content-Security-Policy") == "" {
		t.Fatal(w.Code, w.Header())
	}
	w = perform(s, "POST", "/api/import", "{}", map[string]string{"Content-Type": "text/plain"})
	if w.Code != 415 {
		t.Fatal(w.Code)
	}
}
func TestEndpoints(t *testing.T) {
	s, b := testServer(t)
	for _, path := range []string{"/api/health", "/api/recordings", "/api/recordings/" + b.ID, "/api/recordings/" + b.ID + "/graph", "/api/compare?before=" + b.ID + "&after=" + b.ID, "/"} {
		w := perform(s, "GET", path, "", nil)
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	w := perform(s, "GET", "/api/recordings/missing", "", nil)
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}
func TestImportIntegrityAndDuplicate(t *testing.T) {
	s, b := testServer(t)
	raw, _ := json.Marshal(b)
	w := perform(s, "POST", "/api/import", string(raw), nil)
	if w.Code != 409 {
		t.Fatal(w.Code)
	}
	b.ID = evidence.NewID()
	b.Title = "tampered"
	raw, _ = json.Marshal(b)
	w = perform(s, "POST", "/api/import", string(raw), nil)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	b.Seal()
	raw, _ = json.Marshal(b)
	w = perform(s, "POST", "/api/import", string(raw), nil)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestDemoRejectsCommands(t *testing.T) {
	s, _ := testServer(t)
	for _, body := range []string{`{"scenario":"cmd.exe","mode":"both"}`, `{"scenario":"diagnostic-export","mode":"shell"}`, `{"scenario":"diagnostic-export","mode":"both","command":"whoami"}`, `{} {}`} {
		w := perform(s, "POST", "/api/demo", body, nil)
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	s.busy <- struct{}{}
	w := perform(s, "POST", "/api/demo", `{}`, nil)
	<-s.busy
	if w.Code != 409 {
		t.Fatal(w.Code)
	}
}
func TestOfflineReportEscapesEvidence(t *testing.T) {
	_, b := testServer(t)
	b.Title = `</script><script>alert('xss')</script>`
	b.Seal()
	out, err := Report([]evidence.Bundle{b})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte(b.Title)) {
		t.Fatal("unsafe HTML injection")
	}
	if !bytes.Contains(out, []byte("connect-src 'none'")) || !bytes.Contains(out, []byte("sha256-")) {
		t.Fatal("missing offline CSP")
	}
	if _, err := Report(nil); err == nil {
		t.Fatal("empty report accepted")
	}
	b.Digest = "tampered"
	if _, err := Report([]evidence.Bundle{b}); err == nil {
		t.Fatal("tampered report accepted")
	}
}
func TestNoArbitraryNetworkBind(t *testing.T) {
	s, _ := testServer(t)
	if err := Serve(t.Context(), s.Store, "python", "0.0.0.0:0"); err == nil {
		t.Fatal("non-loopback bind accepted")
	}
}
func TestMethods(t *testing.T) {
	s, _ := testServer(t)
	w := perform(s, http.MethodDelete, "/api/recordings", "", nil)
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}
