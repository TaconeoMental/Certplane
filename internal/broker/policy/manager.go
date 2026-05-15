package policy

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

const watchInterval = 5 * time.Second

type Manager struct {
	path    string
	current atomic.Value // *CompiledPolicy
}

func NewManager(path string) (*Manager, error) {
	m := &Manager{path: path}
	if err := m.Reload(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) Reload() error {
	policy, err := Load(m.path)
	if err != nil {
		return err
	}
	m.current.Store(policy)
	return nil
}

func (m *Manager) Current() *CompiledPolicy {
	current := m.current.Load()
	if current == nil {
		return nil
	}
	p, _ := current.(*CompiledPolicy)
	return p
}

func (m *Manager) Watch(ctx context.Context) {
	var lastMod time.Time
	if info, err := os.Stat(m.path); err == nil {
		lastMod = info.ModTime()
	}

	ticker := time.NewTicker(watchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := os.Stat(m.path)
			if err != nil {
				slog.Warn("policy watch: stat failed", "path", m.path, "error", err)
				continue
			}
			if !info.ModTime().After(lastMod) {
				continue
			}
			lastMod = info.ModTime()
			if err := m.Reload(); err != nil {
				slog.Warn("policy watch: reload failed", "path", m.path, "error", err)
				continue
			}
			slog.Info("policy reloaded", "path", m.path, "hash", m.Current().Hash)
		}
	}
}
