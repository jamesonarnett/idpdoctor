// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
)

// ErrUnknownRef is returned when a handle does not exist in the store.
var ErrUnknownRef = errors.New("unknown input_ref")

// Store holds raw artifacts in memory, keyed by an opaque handle such as
// art_7f3a.... It exists so an agent can call stash_file and then pass the
// handle to every other tool: the raw assertion never has to enter the
// agent's transcript. Nothing is ever written to disk.
type Store struct {
	mu sync.Mutex
	m  map[string][]byte
}

// NewStore returns an empty store.
func NewStore() *Store { return &Store{m: map[string][]byte{}} }

// Put stores a copy of data and returns its handle.
func (s *Store) Put(data []byte) string {
	ref := newRef()
	cp := make([]byte, len(data))
	copy(cp, data)
	s.mu.Lock()
	s.m[ref] = cp
	s.mu.Unlock()
	return ref
}

// PutRef stores data under a caller-chosen handle. The CLI uses it when it
// pre-registers an artifact for an agent: the handle must be known to the
// prompt before the server process exists, so it is derived from the bytes
// (see RefFor) rather than drawn at random. An existing handle is replaced.
func (s *Store) PutRef(ref string, data []byte) {
	cp := make([]byte, len(data))
	copy(cp, data)
	s.mu.Lock()
	s.m[ref] = cp
	s.mu.Unlock()
}

// RefFor derives the deterministic handle PutRef and the CLI agree on:
// "art_" + the first 16 hex chars of SHA-256(data). Deterministic is fine
// here because the handle is a name, not a capability: the store lives in
// one process the caller already owns.
func RefFor(data []byte) string {
	sum := sha256.Sum256(data)
	return "art_" + hex.EncodeToString(sum[:8])
}

// Get returns a copy of the artifact for ref.
func (s *Store) Get(ref string) ([]byte, error) {
	s.mu.Lock()
	data, ok := s.m[ref]
	s.mu.Unlock()
	if !ok {
		return nil, ErrUnknownRef
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return cp, nil
}

// Delete forgets a handle. Missing handles are not an error.
func (s *Store) Delete(ref string) {
	s.mu.Lock()
	delete(s.m, ref)
	s.mu.Unlock()
}

// Len reports how many artifacts are held.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// newRef makes an unguessable handle. 8 random bytes is plenty for an
// in-process map that lives as long as one MCP session.
func newRef() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("redact: crypto/rand failed: " + err.Error())
	}
	return "art_" + hex.EncodeToString(b[:])
}
