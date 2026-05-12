package dnsname

import "testing"

func TestCanonical(t *testing.T) {
	got, err := Canonical("API.WHISPER.CL.")
	if err != nil {
		t.Fatal(err)
	}
	if got != "api.whisper.cl" {
		t.Fatalf("got %q", got)
	}
}

func TestWildcardValidation(t *testing.T) {
	valid := []string{"*.whisper.cl", "*.qa.whisper.cl"}
	invalid := []string{"*.*.whisper.cl", "foo*.whisper.cl", "*.cl"}
	for _, name := range valid {
		if _, err := Canonical(name); err != nil {
			t.Fatalf("%s should be valid: %v", name, err)
		}
	}
	for _, name := range invalid {
		if _, err := Canonical(name); err == nil {
			t.Fatalf("%s should be invalid", name)
		}
	}
}
