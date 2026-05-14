package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// The broker emits audit events through this interface instead of writing
// directly to SQLite, files or stdout. This keeps certificate issuance
// agnostic of the storage backend and allows multiple sinks to be used
// together.
type Recorder interface {
	Record(ctx context.Context, event Event) error
}

// Writes audit events as JSON Lines to an io.Writer
type JSONLRecorder struct {
	mu sync.Mutex
	w  io.Writer
}

func NewJSONLRecorder(w io.Writer) *JSONLRecorder {
	return &JSONLRecorder{w: w}
}

func (r *JSONLRecorder) Record(ctx context.Context, event Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := json.NewEncoder(r.w).Encode(event); err != nil {
		return fmt.Errorf("writing audit event as jsonl: %w", err)
	}

	return nil
}

// Appends audit events to a JSONL file
type FileJSONLRecorder struct {
	path string
	mu   sync.Mutex
}

func NewFileJSONLRecorder(path string) *FileJSONLRecorder {
	return &FileJSONLRecorder{path: path}
}

func (r *FileJSONLRecorder) Record(ctx context.Context, event Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		return fmt.Errorf("creating audit directory: %w", err)
	}

	file, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("opening audit log %q: %w", r.path, err)
	}

	encodeErr := json.NewEncoder(file).Encode(event)
	syncErr := file.Sync()
	closeErr := file.Close()

	if encodeErr != nil {
		return fmt.Errorf("writing audit event to %q: %w", r.path, encodeErr)
	}
	if syncErr != nil {
		return fmt.Errorf("syncing audit log %q: %w", r.path, syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("closing audit log %q: %w", r.path, closeErr)
	}

	return nil
}

// MultiRecorder writes each event to all configured recorders. It attempts
// every recorder even if one fails, then returns the joined error.
type MultiRecorder struct {
	recorders []Recorder
}

func NewMultiRecorder(recorders ...Recorder) *MultiRecorder {
	filtered := make([]Recorder, 0, len(recorders))
	for _, recorder := range recorders {
		if recorder != nil {
			filtered = append(filtered, recorder)
		}
	}
	return &MultiRecorder{recorders: filtered}
}

func (m *MultiRecorder) Record(ctx context.Context, event Event) error {
	var errs []error
	for _, recorder := range m.recorders {
		if err := recorder.Record(ctx, event); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// DiscardRecorder drops audit events...
type DiscardRecorder struct{}

func NewDiscardRecorder() *DiscardRecorder { return &DiscardRecorder{} }

func (r *DiscardRecorder) Record(ctx context.Context, event Event) error { return nil }
