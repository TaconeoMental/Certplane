package audit

import (
	"crypto/rand"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// Returns a random identifier for audit/request correlation
func NewID(prefix string) string {
	id, err := ulid.New(ulid.Timestamp(time.Now().UTC()), rand.Reader)
	if err != nil {
		panic("generate audit id: " + err.Error())
	}

	return prefix + strings.ToLower(id.String())
}
