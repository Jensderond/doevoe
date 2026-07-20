package api

import (
	"encoding/json"
	"net/http"
	"net/mail"
	"strconv"
	"strings"

	"doevoe/internal/store"
)

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

type sendRequest struct {
	From, To, Subject, HTML, Text, ReplyTo string
	Headers                                map[string]string
}

func (s *Server) postEmail(w http.ResponseWriter, r *http.Request) {
	k := s.auth(w, r)
	if k == nil {
		return
	}
	var req sendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, 400, "invalid json: "+err.Error())
		return
	}
	from, err := mail.ParseAddress(req.From)
	if err != nil {
		jsonError(w, 422, "invalid from address")
		return
	}
	to, err := mail.ParseAddress(req.To)
	if err != nil {
		jsonError(w, 422, "invalid to address")
		return
	}
	if req.Subject == "" || (req.HTML == "" && req.Text == "") {
		jsonError(w, 422, "subject and html or text are required")
		return
	}
	domain, err := s.Store.GetDomain(k.DomainID)
	if err != nil {
		jsonError(w, 500, "internal error")
		return
	}
	fromDomain := from.Address[strings.LastIndex(from.Address, "@")+1:]
	if !strings.EqualFold(fromDomain, domain.Name) {
		jsonError(w, 422, "from address must be on domain "+domain.Name)
		return
	}
	if !domain.Verified() {
		jsonError(w, 403, "domain "+domain.Name+" is not verified; complete DNS setup in the doevoe admin before sending")
		return
	}

	idemKey := r.Header.Get("Idempotency-Key")
	if idemKey != "" {
		if existing, err := s.Store.FindByIdempotencyKey(k.ID, idemKey); err == nil && existing != nil {
			writeJSON(w, 200, map[string]any{"id": existing.ID, "status": existing.Status})
			return
		}
	}

	headersJSON := "{}"
	if len(req.Headers) > 0 {
		hb, _ := json.Marshal(req.Headers)
		headersJSON = string(hb)
	}
	id, err := s.Store.EnqueueEmail(&store.Email{
		APIKeyID: k.ID, DomainID: domain.ID,
		From: from.Address, To: to.Address, ReplyTo: req.ReplyTo,
		Subject: req.Subject, BodyHTML: req.HTML, BodyText: req.Text,
		HeadersJSON: headersJSON, IdempotencyKey: idemKey,
	})
	if err != nil {
		jsonError(w, 500, "enqueue failed")
		return
	}
	writeJSON(w, 202, map[string]any{"id": id, "status": "queued"})
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
