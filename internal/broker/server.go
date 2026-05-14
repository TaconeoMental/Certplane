package broker

import (
	"log/slog"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/broker/audit"
	"github.com/TaconeoMental/certplane/internal/broker/issuer"
	"github.com/TaconeoMental/certplane/internal/broker/policy"
	"github.com/TaconeoMental/certplane/internal/broker/ratelimit"
	"github.com/TaconeoMental/certplane/internal/broker/store"
	"golang.org/x/sync/singleflight"
)

type Server struct {
	cfg         *config.BrokerConfig
	policy      *policy.Manager
	store       store.CertificateStore
	issuer      issuer.Issuer
	audit       audit.Recorder
	rateLimiter *ratelimit.Limiter
	failureMode string
	flightGroup singleflight.Group
	logger      *slog.Logger
}

func NewServer(cfg *config.BrokerConfig, pm *policy.Manager, st store.CertificateStore, iss issuer.Issuer, rec audit.Recorder, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		cfg:         cfg,
		policy:      pm,
		store:       st,
		issuer:      iss,
		audit:       rec,
		rateLimiter: ratelimit.New(cfg.RateLimits.PerIdentityPerHour, cfg.RateLimits.PerIdentityProfilePerHour),
		failureMode: cfg.Audit.FailureMode,
		logger:      logger,
	}
}
