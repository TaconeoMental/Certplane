package ratelimit

import (
	"fmt"
	"sync"
	"time"
)

type Limiter struct {
	mu                 sync.Mutex
	perIdentity        int
	perIdentityProfile int
	identity           map[string][]time.Time
	profile            map[string][]time.Time
}

func New(perIdentity, perIdentityProfile int) *Limiter {
	return &Limiter{perIdentity: perIdentity, perIdentityProfile: perIdentityProfile, identity: map[string][]time.Time{}, profile: map[string][]time.Time{}}
}

func (l *Limiter) Allow(identity, profile string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	windowStart := now.Add(-1 * time.Hour)
	l.identity[identity] = prune(l.identity[identity], windowStart)
	profileKey := identity + "\x00" + profile
	l.profile[profileKey] = prune(l.profile[profileKey], windowStart)
	if l.perIdentity > 0 && len(l.identity[identity]) >= l.perIdentity {
		return fmt.Errorf("rate limit exceeded for identity %q", identity)
	}
	if l.perIdentityProfile > 0 && len(l.profile[profileKey]) >= l.perIdentityProfile {
		return fmt.Errorf("rate limit exceeded for identity/profile %q/%q", identity, profile)
	}
	l.identity[identity] = append(l.identity[identity], now)
	l.profile[profileKey] = append(l.profile[profileKey], now)
	return nil
}

func prune(in []time.Time, after time.Time) []time.Time {
	out := in[:0]
	for _, t := range in {
		if t.After(after) {
			out = append(out, t)
		}
	}
	return out
}
