package audit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJSONLRecorder(t *testing.T) {
	var buf bytes.Buffer
	rec := NewJSONLRecorder(&buf)

	if err := rec.Record(context.Background(), Event{EventID: "e1", RequestID: "r1", Timestamp: time.Now(), Type: EventBrokerStarted, Severity: SeverityInfo, Decision: DecisionAllow}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "broker_started") {
		t.Fatalf("audit event not written: %s", buf.String())
	}
}

func TestFileJSONLRecorder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	rec := NewFileJSONLRecorder(path)

	if err := rec.Record(context.Background(), Event{EventID: "e1", RequestID: "r1", Timestamp: time.Now(), Type: EventBrokerStarted, Severity: SeverityInfo, Decision: DecisionAllow}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "broker_started") {
		t.Fatalf("audit event not written: %s", data)
	}
}
