package main

import (
	"breachrewind/internal/collector"
	"breachrewind/internal/demo"
	"breachrewind/internal/evidence"
	"breachrewind/internal/server"
	"breachrewind/internal/storage"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"
)

const help = `BREACH REWIND 1.0.0 — Local-first attack evidence workspace

Usage: rewind <command> [options]

  serve    --addr 127.0.0.1:9847 --db data/rewind.db --python python
  capture  --title "My workload" --timeout 120 -- python sdk/python/example.py
  demo     --scenario all|diagnostic-export|path-traversal|stale-authorization
           --mode both|vulnerable|patched --db data/rewind.db --python python
  record   --input events.jsonl|- --format native|tracee --title "Capture"
           --db data/rewind.db
  import   --input recording.json --db data/rewind.db
  list     --db data/rewind.db
  inspect  --id RECORDING_ID --db data/rewind.db
  compare  --before ID --after ID --db data/rewind.db
  export   --id ID --out report.html|recording.json --format html|json
           --baseline ID (optional, HTML only) --db data/rewind.db
  verify   --input recording.json
  version

No command initializes Git, uploads recordings, or runs imported code.
Native/Tracee record accepts finite files or piped JSONL (terminate source with EOF).
All imported/stored evidence is redacted; review it again before sharing.
`

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "rewind:", err)
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Fprint(out, help)
		return nil
	}
	if args[0] == "version" {
		fmt.Fprintln(out, "BREACH REWIND 1.0.0")
		return nil
	}
	command := args[0]
	valid := map[string]bool{"serve": true, "capture": true, "demo": true, "record": true, "import": true, "list": true, "inspect": true, "compare": true, "export": true, "verify": true}
	if !valid[command] {
		return errors.New("unknown command; use rewind help")
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	db := flags.String("db", "data/rewind.db", "local SQLite database")
	python := flags.String("python", "python", "Python 3.11+ executable")
	addr := flags.String("addr", "127.0.0.1:9847", "loopback listen address")
	timeout := flags.Int("timeout", 120, "capture timeout in seconds, 1-3600")
	scenario := flags.String("scenario", "all", "demonstration scenario")
	mode := flags.String("mode", "both", "demonstration mode")
	input := flags.String("input", "", "input path or - for stdin")
	format := flags.String("format", "", "native, tracee, html or json")
	title := flags.String("title", "Recorded session", "recording title")
	id := flags.String("id", "", "recording ID")
	before := flags.String("before", "", "before recording ID")
	after := flags.String("after", "", "after recording ID")
	output := flags.String("out", "", "new output path (never overwritten)")
	baseline := flags.String("baseline", "", "second recording for HTML report")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 && command != "capture" {
		return errors.New("unexpected positional arguments")
	}
	emit := func(v any) error { enc := json.NewEncoder(out); enc.SetIndent("", "  "); return enc.Encode(v) }
	readInput := func() (io.ReadCloser, error) {
		if *input == "" {
			return nil, errors.New("--input is required")
		}
		if *input == "-" {
			return io.NopCloser(os.Stdin), nil
		}
		return os.Open(*input)
	}
	if command == "verify" {
		r, err := readInput()
		if err != nil {
			return err
		}
		defer r.Close()
		b, err := evidence.Decode(r)
		if err != nil {
			return err
		}
		return emit(map[string]any{"valid": true, "id": b.ID, "digest": b.Digest, "note": "Checksum confirms content consistency, not source authenticity."})
	}
	store, err := storage.Open(*db)
	if err != nil {
		return err
	}
	defer store.Close()
	switch command {
	case "capture":
		if *timeout < 1 || *timeout > 3600 {
			return errors.New("timeout must be 1-3600 seconds")
		}
		captureCtx, cancel := context.WithTimeout(ctx, time.Duration(*timeout)*time.Second)
		defer cancel()
		b, err := collector.Capture(captureCtx, flags.Args(), *title)
		if err != nil {
			return err
		}
		if err = store.Put(b); err != nil {
			return err
		}
		fmt.Fprintln(out, b.ID)
		return nil
	case "serve":
		return server.Serve(ctx, store, *python, *addr)
	case "list":
		items, err := store.List()
		if err != nil {
			return err
		}
		return emit(items)
	case "inspect":
		b, err := store.Get(*id)
		if err != nil {
			return err
		}
		return emit(b)
	case "compare":
		a, err := store.Get(*before)
		if err != nil {
			return err
		}
		b, err := store.Get(*after)
		if err != nil {
			return err
		}
		return emit(evidence.Compare(a, b))
	case "demo":
		scenarios := []string{*scenario}
		if *scenario == "all" {
			scenarios = demo.Scenarios
		}
		modes := []string{*mode}
		if *mode == "both" {
			modes = []string{"vulnerable", "patched"}
		}
		bundles := []evidence.Bundle{}
		for _, s := range scenarios {
			for _, m := range modes {
				runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				b, err := demo.Run(runCtx, *python, s, m)
				cancel()
				if err != nil {
					return err
				}
				bundles = append(bundles, b)
			}
		}
		if err = store.PutMany(bundles); err != nil {
			return err
		}
		for _, b := range bundles {
			fmt.Fprintf(out, "%s  %-22s %-10s %d events\n", b.ID, b.Scenario, b.Mode, len(b.Events))
		}
		return nil
	case "record", "import":
		r, err := readInput()
		if err != nil {
			return err
		}
		defer r.Close()
		var b evidence.Bundle
		if command == "record" {
			f := *format
			if f == "" {
				f = "native"
			}
			b, err = collector.Read(r, f, *title)
		} else {
			b, err = evidence.Decode(r)
			if err == nil {
				b.Redact()
				err = b.Seal()
			}
		}
		if err != nil {
			return err
		}
		if err = store.Put(b); err != nil {
			return err
		}
		fmt.Fprintln(out, b.ID)
		return nil
	case "export":
		if *output == "" {
			return errors.New("--out is required")
		}
		b, err := store.Get(*id)
		if err != nil {
			return err
		}
		var data []byte
		f := *format
		if f == "" {
			f = "html"
		}
		switch f {
		case "json":
			data, err = json.MarshalIndent(b, "", "  ")
		case "html":
			bundles := []evidence.Bundle{b}
			if *baseline != "" {
				base, e := store.Get(*baseline)
				if e != nil {
					return e
				}
				bundles = append(bundles, base)
			}
			data, err = server.Report(bundles)
		default:
			return errors.New("export format must be html or json")
		}
		if err != nil {
			return err
		}
		file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(data)
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
		fmt.Fprintln(out, *output)
		return nil
	}
	return nil
}
