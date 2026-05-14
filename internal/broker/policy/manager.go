package policy

import "sync/atomic"

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
