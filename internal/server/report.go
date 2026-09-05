package server

import (
	"breachrewind/internal/evidence"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

// Report embeds the exact production viewer and escaped evidence in one offline file.
// The CSP hashes executable code, while disallowing networking and active evidence.
func Report(bundles []evidence.Bundle) ([]byte, error) {
	if len(bundles) < 1 || len(bundles) > 2 {
		return nil, errors.New("a report needs one or two recordings")
	}
	// Clone before redaction: callers retain their original in-memory evidence.
	raw, err := json.Marshal(bundles)
	if err != nil {
		return nil, err
	}
	var clean []evidence.Bundle
	if err = json.Unmarshal(raw, &clean); err != nil {
		return nil, err
	}
	for i := range clean {
		if err = clean[i].Validate(); err != nil {
			return nil, err
		}
		if clean[i].Checksum() != clean[i].Digest {
			return nil, errors.New("invalid report evidence checksum")
		}
		clean[i].Redact()
		if err = clean[i].Seal(); err != nil {
			return nil, err
		}
	}
	data, err := json.Marshal(clean)
	if err != nil {
		return nil, err
	}
	var js, css []byte
	err = fs.WalkDir(UI, "ui/assets", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".js") {
			if js != nil {
				return errors.New("report requires a single JavaScript bundle")
			}
			js, err = UI.ReadFile(path)
		}
		if strings.HasSuffix(path, ".css") {
			var b []byte
			b, err = UI.ReadFile(path)
			css = append(css, b...)
		}
		return err
	})
	if err != nil || len(js) == 0 {
		return nil, errors.New("build viewer assets before exporting HTML")
	}
	// Avoid closing script/style elements in trusted bundled code, too.
	if strings.Contains(strings.ToLower(string(js)), "</script") || strings.Contains(strings.ToLower(string(css)), "</style") {
		return nil, errors.New("unsafe asset delimiter")
	}
	hash := sha256.Sum256(js)
	csp := "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'"
	html := fmt.Sprintf(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="%s"><meta name="referrer" content="no-referrer"><title>BREACH REWIND — Offline evidence</title><style>%s</style></head><body><div id="root"></div><script type="application/json" id="rewind-evidence">%s</script><script type="module">%s</script></body></html>`, csp, css, data, js)
	return []byte(html), nil
}
