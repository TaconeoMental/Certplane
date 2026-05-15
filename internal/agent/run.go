package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/ca"
	"github.com/TaconeoMental/certplane/internal/fileutil"
	"github.com/TaconeoMental/certplane/internal/pki"
)

func Run(ctx context.Context, cfg *config.AgentConfig, identityCA ca.IdentityCA) error {
	lockPath := filepath.Join(cfg.StateDir, "agent.lock")
	lock, err := fileutil.AcquireLock(lockPath)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()

	exists, err := fileutil.FileExists(cfg.Identity.Cert)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("identity cert not found at %s, run enroll first", cfg.Identity.Cert)
	}

	client, err := NewBrokerClient(cfg)
	if err != nil {
		return err
	}

	slog.Info("agent run started", "certificates", len(cfg.Certificates))

	if err := RenewIdentityIfNeeded(ctx, cfg, identityCA); err != nil {
		slog.Error("identity renewal failed", "error", err)
		return fmt.Errorf("renewing identity: %w", err)
	}

	for i := range cfg.Certificates {
		if err := ensureServiceCertificate(ctx, client, &cfg.Certificates[i]); err != nil {
			slog.Error("service certificate processing failed", "certificate", cfg.Certificates[i].Name, "profile", cfg.Certificates[i].Profile, "error", err)
			return err
		}
	}

	slog.Info("agent run completed")
	return nil
}

func ensureServiceCertificate(ctx context.Context, client *BrokerClient, certCfg *config.CertConfig) error {
	keyExisted := true
	if exists, err := fileutil.FileExists(certCfg.Key); err != nil {
		return err
	} else if !exists {
		keyExisted = false
	}

	key, _, err := pki.EnsureECDSAPrivateKey(certCfg.Key)
	if err != nil {
		return fmt.Errorf("ensuring service key for %s: %w", certCfg.Name, err)
	}
	if keyExisted {
		slog.Debug("service key reused", "certificate", certCfg.Name, "key", certCfg.Key)
	} else {
		slog.Info("service key generated", "certificate", certCfg.Name, "key", certCfg.Key)
	}

	exists, err := fileutil.FileExists(certCfg.Cert)
	if err != nil {
		return err
	}
	if exists {
		certData, err := os.ReadFile(certCfg.Cert)
		if err != nil {
			return fmt.Errorf("reading certificate %s: %w", certCfg.Cert, err)
		}
		cert, err := pki.ParseCertificatePEM(certData)
		if err != nil {
			return fmt.Errorf("parsing certificate %s: %w", certCfg.Cert, err)
		}
		if err := pki.CertificateMatchesPrivateKey(cert, key); err != nil {
			return fmt.Errorf("existing certificate for %s does not match key: %w", certCfg.Name, err)
		}
		if !pki.ExpiresWithin(cert, certCfg.RenewBefore) {
			slog.Info("certificate skipped, not in renewal window", "certificate", certCfg.Name, "profile", certCfg.Profile, "not_after", cert.NotAfter.Format(time.RFC3339))
			return nil
		}
	}

	csrPEM, err := pki.GenerateServiceCSR(key, certCfg.DNSNames)
	if err != nil {
		return fmt.Errorf("generating service CSR for %s: %w", certCfg.Name, err)
	}

	slog.Info("requesting certificate", "certificate", certCfg.Name, "profile", certCfg.Profile, "csr_sha256", pki.CSRFingerprint(csrPEM))
	bundle, err := client.Issue(ctx, certCfg.Profile, csrPEM)
	if err != nil {
		return fmt.Errorf("requesting certificate for %s: %w", certCfg.Name, err)
	}

	cert, err := pki.ParseCertificatePEM(bundle.CertPEM)
	if err != nil {
		return fmt.Errorf("parsing broker certificate for %s: %w", certCfg.Name, err)
	}
	if err := pki.CertificateMatchesPrivateKey(cert, key); err != nil {
		return fmt.Errorf("broker returned certificate for %s that does not match local key: %w", certCfg.Name, err)
	}
	if err := pki.CertificateHasExactDNSNames(cert, certCfg.DNSNames); err != nil {
		return fmt.Errorf("broker returned certificate for %s with unexpected DNS names: %w", certCfg.Name, err)
	}

	if err := bundle.WriteToDisk(certCfg.Cert, certCfg.Chain, certCfg.FullChain); err != nil {
		return fmt.Errorf("installing certificate bundle for %s: %w", certCfg.Name, err)
	}
	slog.Info("certificate installed", "certificate", certCfg.Name, "profile", certCfg.Profile, "serial", bundle.LeafSerialNumber, "not_after", bundle.NotAfter.Format(time.RFC3339))

	if strings.TrimSpace(certCfg.ReloadCommand) != "" {
		slog.Info("reload started", "certificate", certCfg.Name, "command", certCfg.ReloadCommand)
		out, err := runReload(ctx, certCfg.ReloadCommand, certCfg.ReloadTimeout)
		if err != nil {
			slog.Error("reload failed", "certificate", certCfg.Name, "command", certCfg.ReloadCommand, "output", out, "error", err)
			return fmt.Errorf("reload for %s failed: %w", certCfg.Name, err)
		}
		slog.Info("reload completed", "certificate", certCfg.Name, "command", certCfg.ReloadCommand, "output", out)
	}
	return nil
}

func runReload(ctx context.Context, command string, timeout time.Duration) (string, error) {
	reloadCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(reloadCtx, "/bin/sh", "-c", command)
	out, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(out))
	if reloadCtx.Err() != nil {
		return trimmed, fmt.Errorf("reload command timed out after %s", timeout)
	}
	if err != nil {
		return trimmed, fmt.Errorf("reload command failed: %w: %s", err, trimmed)
	}
	return trimmed, nil
}
