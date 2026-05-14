package issuer

import (
	"context"

	"github.com/TaconeoMental/certplane/internal/pki"
)

type IssueRequest struct {
	ProfileName         string
	DNSNames            []string
	CSRPEM              []byte
	ACMEChallenge       string
	ACMECredentialsName string
}

type Issuer interface {
	Name() string
	Directory() string
	AccountKeyID() string
	Issue(ctx context.Context, req IssueRequest) (*pki.Bundle, error)
}
