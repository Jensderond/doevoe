package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"doevoe/internal/send"
	"doevoe/internal/store"
)

// maxRequestBodyBytes caps the size of a POST /api/v1/emails body. Without
// this, an unauthenticated-in-effect (or malicious authenticated) caller
// could send an arbitrarily large body and exhaust memory/disk decoding and
// storing it; 10MB comfortably covers any legitimate transactional email
// (including a large embedded HTML body) while bounding the worst case.
const maxRequestBodyBytes = 10 << 20 // 10MB

type Server struct{ Store *store.Store }

func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/emails", s.postEmail)
	mux.HandleFunc("GET /api/v1/emails/{id}", s.getEmail)
}

func (s *Server) auth(w http.ResponseWriter, r *http.Request) *store.APIKey {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" || token == r.Header.Get("Authorization") {
		jsonError(w, 401, "missing bearer token")
		return nil
	}
	k, err := s.Store.GetAPIKeyByHash(store.HashAPIKey(token))
	if err != nil || k == nil {
		jsonError(w, 401, "invalid api key")
		return nil
	}
	s.Store.TouchAPIKey(k.ID, store.Now())
	return k
}

// sendRequest mirrors the public API's JSON request body. Explicit tags are
// required on every field: without them, encoding/json's case-insensitive
// fallback matches "ReplyTo" against keys like "replyto" or "REPLYTO", but
// NOT against the spec's snake_case "reply_to" (the fallback ignores case,
// not underscores), so a caller-supplied reply_to would silently decode to
// "" instead of erroring or populating the field. Every other field happens
// to work by accident today because none of the others contain an
// underscore in the wire format.
type sendRequest struct {
	From    string            `json:"from"`
	To      string            `json:"to"`
	Subject string            `json:"subject"`
	HTML    string            `json:"html"`
	Text    string            `json:"text"`
	ReplyTo string            `json:"reply_to"`
	Headers map[string]string `json:"headers"`
}

func (s *Server) postEmail(w http.ResponseWriter, r *http.Request) {
	k := s.auth(w, r)
	if k == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var req sendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			jsonError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		jsonError(w, 400, "invalid json: "+err.Error())
		return
	}
	res, serr := send.Send(s.Store, k.ID, k.DomainID, send.Input{
		From: req.From, To: req.To, Subject: req.Subject, HTML: req.HTML, Text: req.Text,
		ReplyTo: req.ReplyTo, Headers: req.Headers,
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
	})
	if serr != nil {
		jsonError(w, serr.Code, serr.Msg)
		return
	}
	code := 202
	if res.Replay {
		code = 200
	}
	writeJSON(w, code, map[string]any{"id": res.ID, "status": res.Status})
}

func (s *Server) getEmail(w http.ResponseWriter, r *http.Request) {
	k := s.auth(w, r)
	if k == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		jsonError(w, 400, "bad id")
		return
	}
	e, err := s.Store.GetEmail(id)
	if err != nil || e.DomainID != k.DomainID {
		jsonError(w, 404, "not found")
		return
	}
	writeJSON(w, 200, map[string]any{
		"id": e.ID, "status": e.Status, "attempts": e.Attempts,
		"last_error": e.LastError, "created_at": e.CreatedAt, "sent_at": e.SentAt,
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
