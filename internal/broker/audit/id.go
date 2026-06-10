package audit

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// Returns a random identifier for audit/request correlation
func NewID(prefix string) (string, error) {
	id, err := ulid.New(ulid.Timestamp(time.Now().UTC()), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate audit id: %w", err)
	}
	return prefix + strings.ToLower(id.String()), nil
}
