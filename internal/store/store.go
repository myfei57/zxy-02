package store

import (
	"path/filepath"
	"sort"
	"sync"
)

// State is the central in-memory + file-backed registry.
type State struct {
	mu           sync.RWMutex
	root         string
	requests     map[string]*Request
	certificates map[string]*Certificate
	revocations  []RevocationEntry
	crl          *CrlState
	keys         map[string]*KeyRecord
	windows      map[string]*RenewalWindow
	audit        []AuditEntry
}

// NewState creates a State rooted at dir.
func NewState(dir string) *State {
	return &State{
		root:         dir,
		requests:     make(map[string]*Request),
		certificates: make(map[string]*Certificate),
		crl:          &CrlState{},
		keys:         make(map[string]*KeyRecord),
		windows:      make(map[string]*RenewalWindow),
	}
}

func (s *State) PutRequest(r *Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[r.ID] = r
}

func (s *State) Request(id string) (*Request, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.requests[id]
	return r, ok
}

func (s *State) ListRequests() []*Request {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Request, 0, len(s.requests))
	for _, r := range s.requests {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *State) PutCertificate(c *Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certificates[c.ID] = c
	return SaveJSON(s.certPath(c.ID), c)
}

func (s *State) Certificate(id string) (*Certificate, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.certificates[id]
	return c, ok
}

func (s *State) ListCertificates() []*Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Certificate, 0, len(s.certificates))
	for _, c := range s.certificates {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Serial < out[j].Serial })
	return out
}

func (s *State) AppendRevocation(e RevocationEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revocations = append(s.revocations, e)
	return SaveJSON(filepath.Join(s.root, "revocations.json"), s.revocations)
}

func (s *State) Revocations() []RevocationEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RevocationEntry, len(s.revocations))
	copy(out, s.revocations)
	return out
}

func (s *State) SetCrl(c *CrlState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.crl = c
	return SaveJSON(filepath.Join(s.root, "crl.json"), c)
}

func (s *State) Crl() *CrlState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := *s.crl
	return &cp
}

func (s *State) PutKey(k *KeyRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[k.CertID] = k
}

func (s *State) Key(certID string) (*KeyRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[certID]
	return k, ok
}

func (s *State) PutWindow(w *RenewalWindow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.windows[w.CertID] = w
}

func (s *State) Window(certID string) (*RenewalWindow, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	w, ok := s.windows[certID]
	return w, ok
}

func (s *State) AppendAudit(e AuditEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = append(s.audit, e)
}

func (s *State) Audit() []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditEntry, len(s.audit))
	copy(out, s.audit)
	return out
}

// ReplaceAudit swaps the full audit trail (used by trimming).
func (s *State) ReplaceAudit(entries []AuditEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = append([]AuditEntry(nil), entries...)
}

// Save persists the in-memory registry to disk.
func (s *State) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	payload := map[string]any{
		"requests":     s.requests,
		"certificates": s.certificates,
		"keys":         s.keys,
		"windows":      s.windows,
	}
	return SaveJSON(filepath.Join(s.root, "state.json"), payload)
}

// Load restores previously saved state.
func (s *State) Load() error {
	payload := struct {
		Requests     map[string]*Request       `json:"requests"`
		Certificates map[string]*Certificate   `json:"certificates"`
		Keys         map[string]*KeyRecord     `json:"keys"`
		Windows      map[string]*RenewalWindow `json:"windows"`
	}{}
	if err := LoadJSON(filepath.Join(s.root, "state.json"), &payload); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range payload.Requests {
		s.requests[id] = r
	}
	for id, c := range payload.Certificates {
		s.certificates[id] = c
	}
	for id, k := range payload.Keys {
		s.keys[id] = k
	}
	for id, w := range payload.Windows {
		s.windows[id] = w
	}
	var revocations []RevocationEntry
	if err := LoadJSON(filepath.Join(s.root, "revocations.json"), &revocations); err != nil {
		return err
	}
	s.revocations = revocations
	var crl CrlState
	if err := LoadJSON(filepath.Join(s.root, "crl.json"), &crl); err != nil {
		return err
	}
	s.crl = &crl
	return nil
}

func (s *State) certPath(id string) string {
	return filepath.Join(s.root, "certs", id+".json")
}
