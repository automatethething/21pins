package store

// ValidateSSHToken is deliberately separate from historical proxy wildcard
// semantics. A proxy:* token is never an SSH capability.
func (s *Store) ValidateSSHToken(raw, scope string) (TokenRecord, bool) {
	h := tokenHash(raw)
	if h == "" || (scope != "ssh:use" && scope != "ssh:approve") {
		return TokenRecord{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := validateStatePath(s.path); err != nil {
		return TokenRecord{}, false
	}
	if err := s.reloadLocked(); err != nil {
		return TokenRecord{}, false
	}
	for _, t := range s.state.Tokens {
		if t.TokenHash != h || t.RevokedAt != "" {
			continue
		}
		allowed := false
		for _, v := range t.Scopes {
			if v == scope {
				allowed = true
			}
		}
		if !allowed {
			return TokenRecord{}, false
		}
		count := 0
		for _, other := range s.state.Tokens {
			if other.Name == t.Name && other.RevokedAt == "" {
				count++
			}
		}
		if count != 1 {
			return TokenRecord{}, false
		}
		return t, true
	}
	return TokenRecord{}, false
}
