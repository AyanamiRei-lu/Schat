package directory

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// HTTP surface for the prekey directory.
//
//	PUT    /api/v1/keys/{identity}   publish or replace a bundle
//	GET    /api/v1/keys/{identity}   fetch a bundle, consuming one one-time prekey
//	DELETE /api/v1/keys/{identity}   withdraw a bundle
//
// The handler is deliberately unable to do anything else: it holds no key, performs no
// cryptography, and never inspects a bundle beyond the structural checks in
// Bundle.Validate. Keeping the relay's prekey role this narrow is what lets the claim
// "the server contains no code that could read a message" stay true.
func (d *Directory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	identity := strings.TrimPrefix(r.URL.Path, "/api/v1/keys/")
	if identity == "" || identity == r.URL.Path {
		writeError(w, http.StatusNotFound, "no identity key in the path")
		return
	}

	switch r.Method {
	case http.MethodPut:
		d.handlePublish(w, r)
	case http.MethodGet:
		d.handleFetch(w, identity)
	case http.MethodDelete:
		d.handleWithdraw(w, identity)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (d *Directory) handlePublish(w http.ResponseWriter, r *http.Request) {
	// Bound the body before reading it. A relay that reads whatever it is sent can be
	// made to allocate without limit by a single client.
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBundleBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read the request body")
		return
	}
	if len(body) > MaxBundleBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "bundle exceeds the size limit")
		return
	}

	var bundle Bundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		writeError(w, http.StatusBadRequest, "bundle is not valid JSON")
		return
	}

	key, err := d.Publish(bundle)
	switch {
	case errors.Is(err, ErrBadBundle):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrFull):
		writeError(w, http.StatusServiceUnavailable, "the directory is at capacity")
	case err != nil:
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeJSON(w, http.StatusOK, map[string]any{"identity": key})
	}
}

func (d *Directory) handleFetch(w http.ResponseWriter, identity string) {
	bundle, err := d.Fetch(identity)
	switch {
	case errors.Is(err, ErrNotFound):
		// 404 with a clear message: a peer that cannot find a bundle should say so
		// rather than fall back to something unverified.
		writeError(w, http.StatusNotFound, "no bundle published for that identity")
	case errors.Is(err, ErrInvalidIdentity):
		writeError(w, http.StatusBadRequest, err.Error())
	case err != nil:
		writeError(w, http.StatusInternalServerError, "directory error")
	default:
		writeJSON(w, http.StatusOK, bundle)
	}
}

func (d *Directory) handleWithdraw(w http.ResponseWriter, identity string) {
	key, err := ParseKey(identity)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	d.mu.Lock()
	_, existed := d.entries[key]
	delete(d.entries, key)
	d.mu.Unlock()

	if !existed {
		writeError(w, http.StatusNotFound, "no bundle published for that identity")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"identity": key, "withdrawn": true})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}
