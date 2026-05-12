package dnsname

// ABSOLUTA Y TOTALMENTE ARBITRARIO NADA DE RFC NADA DE ESTANDARES
// TODO VALDAR Y CAMBIAR

import (
	"fmt"
	"sort"
	"strings"
)

func Canonical(name string) (string, error) {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	name = strings.ToLower(name)

	if name == "" {
		return "", fmt.Errorf("empty DNS name")
	}
	if strings.ContainsAny(name, " \t\n\r") {
		return "", fmt.Errorf("DNS name %q contains whitespace", name)
	}
	if strings.Contains(name, "..") {
		return "", fmt.Errorf("DNS name %q contains empty label", name)
	}
	for _, r := range name {
		if r > 127 {
			return "", fmt.Errorf("DNS name %q is not ASCII; use punycode before passing it to certplane", name)
		}
	}

	if strings.Contains(name, "*") && !IsValidWildcard(name) {
		return "", fmt.Errorf("invalid wildcard DNS name %q", name)
	}

	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("DNS name %q must have at least two labels", name)
	}
	for _, label := range labels {
		if label == "" {
			return "", fmt.Errorf("DNS name %q contains empty label", name)
		}
		if len(label) > 63 {
			return "", fmt.Errorf("DNS label %q is too long", label)
		}
		if label != "*" {
			if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return "", fmt.Errorf("DNS label %q cannot start or end with '-'", label)
			}
			for _, r := range label {
				if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
					return "", fmt.Errorf("DNS label %q contains invalid character %q", label, r)
				}
			}
		}
	}

	return name, nil
}

func CanonicalList(names []string) ([]string, error) {
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		canonical, err := Canonical(name)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	sort.Strings(out)
	return out, nil
}

func IsValidWildcard(name string) bool {
	if !strings.HasPrefix(name, "*.") {
		return false
	}
	if strings.Count(name, "*") != 1 {
		return false
	}
	rest := strings.TrimPrefix(name, "*.")
	labels := strings.Split(rest, ".")
	return len(labels) >= 2 && labels[0] != "" && labels[1] != ""
}

func EqualSet(a, b []string) bool {
	ca, err := CanonicalList(a)
	if err != nil {
		return false
	}
	cb, err := CanonicalList(b)
	if err != nil {
		return false
	}
	if len(ca) != len(cb) {
		return false
	}
	for i := range ca {
		if ca[i] != cb[i] {
			return false
		}
	}
	return true
}
