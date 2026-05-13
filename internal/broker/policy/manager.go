package policy

import "sync/atomic"

// Manager keeps the currently active compiled policy.
//
// Policies are loaded from the YAML file, validated, normalized and compiled
// before they are used by request handlers. These handlers only interact with
// the compiled snapshot, which avoids re parsing on every request.
//
// Reloads are also atomic, which means that a new policy replaces the current
// one only after it has been fully loaded and validated. If a reload fails,
// the previous valid policy remains active.
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
	return current.(*CompiledPolicy)
}
