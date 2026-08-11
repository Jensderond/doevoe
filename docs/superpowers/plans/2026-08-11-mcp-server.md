# MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Embed a Model Context Protocol (MCP) server in the doevoe binary exposing seven admin-scoped tools — `send_email`, `get_email_status`, `create_domain`, `verify_domain`, `create_api_key`, `revoke_api_key`, `get_sending_stats` — over Streamable HTTP at `/mcp`, gated by a new `DOEVOE_MCP_TOKEN` bearer secret.

**Architecture:** Two small extractions first (send-email validation/enqueue out of `internal/api`, domain create/verify out of `internal/admin` + `cmd/doevoe`), so the HTTP API, admin UI, and MCP tools share one implementation of each invariant. Then a new `internal/mcpserver` package built on the official MCP Go SDK (`mcp.NewServer` + generic `mcp.AddTool`, which generates JSON schemas from typed input/output structs), mounted on the existing single mux behind constant-time bearer auth. MCP is fail-closed: the endpoint is not mounted at all unless `DOEVOE_MCP_TOKEN` is set.

**Tech Stack:** Go 1.25, `github.com/modelcontextprotocol/go-sdk v1.7.0` (the only new dependency; targets MCP spec 2026-07-28 and negotiates down to 2024-11-05 per connection, so the SDK handles all wire-level lifecycle — initialize handshake or stateless `_meta`, `server/discover`, Streamable HTTP framing — and we never hand-roll JSON-RPC).

## Global Constraints

- `go vet ./...` and `go test ./...` must pass at every commit (matches CI in `.github/workflows/docker.yml`).
- Existing HTTP API and admin UI behavior must not change: existing tests in `internal/api`, `internal/admin`, `internal/store` are the regression net. Error **messages and status codes** in the send path must stay byte-identical (tests assert them).
- Money-quote invariants preserved verbatim: indeterminate DNS results are **never persisted** (see comment on `dnscheck.Result`), and every send is fully validated **before** anything is enqueued (a queued email must never be unsendable).
- MCP is disabled unless `DOEVOE_MCP_TOKEN` is set (fail-closed). Token comparison uses `crypto/subtle.ConstantTimeCompare`.
- Timestamps are RFC3339 strings via `store.Now()` / `store.FmtTime()` — never `time.Time` in the store layer.
- MCP sends use `APIKeyID: 0` (same convention as `notify.Notifier.enqueue`, which enqueues system emails without an API key; the `api_key_id` column is a nullable, unenforced reference).
- Tool names (stable identifiers, snake_case): `send_email`, `get_email_status`, `create_domain`, `verify_domain`, `create_api_key`, `revoke_api_key`, `get_sending_stats`.
- New code follows repo comment style: comments state constraints the code can't show, nothing else.

---

### Task 1: Extract `internal/send` (shared send-email validation + enqueue)

The whole validation + idempotency + enqueue pipeline of `POST /api/v1/emails` moves into a new package callable without an `http.ResponseWriter`, so Task 4's MCP tool can reuse it. `api.postEmail` keeps only: auth, body-size cap, JSON decode, and response writing.

**Files:**
- Create: `internal/send/send.go`
- Create: `internal/send/send_test.go`
- Modify: `internal/api/api.go` (replace lines 78–186: validation block, `enqueueOrReplay`, and the enqueue call move out)

**Interfaces:**
- Consumes: `store.Store` methods (`GetDomain`, `FindByIdempotencyKey`, `EnqueueEmail`), `delivery.ValidateHeaderValue/ValidateHeader/FormatAddress`.
- Produces (used by Task 4 and by `internal/api`):
  ```go
  package send
  type Input struct {
      From, To, Subject, HTML, Text, ReplyTo string
      Headers                                map[string]string
      IdempotencyKey                         string
  }
  type Result struct {
      ID     int64
      Status string
      Replay bool // idempotent replay: HTTP surface maps this to 200 instead of 202
  }
  type Error struct { // HTTP-shaped so both surfaces can map it
      Code int    // 422, 403, or 500
      Msg  string
  }
  func (e *Error) Error() string
  func Send(st *store.Store, apiKeyID, domainID int64, in Input) (Result, *Error)
  ```

- [ ] **Step 1: Write the failing test**

`internal/send/send_test.go`:

```go
package send

import (
	"path/filepath"
	"testing"

	"doevoe/internal/store"
)

func setup(t *testing.T, verified bool) (*store.Store, *store.Domain, *store.APIKey) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	d, err := s.CreateDomain("example.com", "mail1", "PEM")
	if err != nil {
		t.Fatal(err)
	}
	if verified {
		s.SetDomainVerification(d.ID, true, true, true, store.Now())
		d, _ = s.GetDomain(d.ID)
	}
	_, hash, err := store.GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.CreateAPIKey("test", d.ID, hash)
	if err != nil {
		t.Fatal(err)
	}
	return s, d, &store.APIKey{ID: id, DomainID: d.ID}
}

func TestSendEnqueues(t *testing.T) {
	s, d, k := setup(t, true)
	res, serr := Send(s, k.ID, d.ID, Input{
		From: "hi@example.com", To: "you@other.com", Subject: "s", Text: "b",
	})
	if serr != nil {
		t.Fatalf("unexpected error: %v", serr)
	}
	if res.Status != "queued" || res.Replay || res.ID == 0 {
		t.Fatalf("got %+v", res)
	}
	e, err := s.GetEmail(res.ID)
	if err != nil || e.From != "hi@example.com" {
		t.Fatalf("stored email: %+v err=%v", e, err)
	}
}

func TestSendUnverifiedDomainFailsClosed(t *testing.T) {
	s, d, k := setup(t, false)
	_, serr := Send(s, k.ID, d.ID, Input{
		From: "hi@example.com", To: "you@other.com", Subject: "s", Text: "b",
	})
	if serr == nil || serr.Code != 403 {
		t.Fatalf("want 403, got %+v", serr)
	}
}

func TestSendWrongFromDomain(t *testing.T) {
	s, d, k := setup(t, true)
	_, serr := Send(s, k.ID, d.ID, Input{
		From: "hi@elsewhere.com", To: "you@other.com", Subject: "s", Text: "b",
	})
	if serr == nil || serr.Code != 422 {
		t.Fatalf("want 422, got %+v", serr)
	}
}

func TestSendIdempotentReplay(t *testing.T) {
	s, d, k := setup(t, true)
	in := Input{From: "hi@example.com", To: "you@other.com", Subject: "s", Text: "b", IdempotencyKey: "abc"}
	first, serr := Send(s, k.ID, d.ID, in)
	if serr != nil {
		t.Fatal(serr)
	}
	second, serr := Send(s, k.ID, d.ID, in)
	if serr != nil {
		t.Fatal(serr)
	}
	if !second.Replay || second.ID != first.ID {
		t.Fatalf("want replay of %d, got %+v", first.ID, second)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/send/... -v`
Expected: FAIL — package does not exist / `Send` undefined.

- [ ] **Step 3: Write the implementation**

`internal/send/send.go` — this is a **move**, not a rewrite: the validation sequence, error messages, and the `enqueueOrReplay` function (with its full comment) come from `internal/api/api.go:78-186` unchanged. Error strings must stay byte-identical.

```go
// Package send holds the shared send-email pipeline: validation, the
// idempotency pre-check, and enqueueing. Both the public JSON API and the
// MCP server call Send, so every send — regardless of surface — is fully
// validated before anything is enqueued and a queued email can never be
// permanently unsendable.
package send

import (
	"encoding/json"
	"net/mail"
	"strings"

	"doevoe/internal/delivery"
	"doevoe/internal/store"
)

type Input struct {
	From, To, Subject, HTML, Text, ReplyTo string
	Headers                                map[string]string
	IdempotencyKey                         string
}

type Result struct {
	ID     int64
	Status string
	Replay bool
}

// Error carries an HTTP-shaped status code (422/403/500) so the JSON API
// can map it directly and the MCP surface can use Msg as the tool error.
type Error struct {
	Code int
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

// Send validates in, applies the idempotency pre-check scoped to apiKeyID,
// and enqueues the email on the domain identified by domainID. apiKeyID is
// 0 for admin/MCP-originated sends (same convention as system
// notifications); it scopes idempotency keys and attributes the email to
// the key in the admin UI. The validation order (and every error message)
// is load-bearing: internal/api's tests assert them, and validation must
// complete before any row is written.
func Send(st *store.Store, apiKeyID, domainID int64, in Input) (Result, *Error) {
	from, err := mail.ParseAddress(in.From)
	if err != nil {
		return Result{}, &Error{422, "invalid from address"}
	}
	to, err := mail.ParseAddress(in.To)
	if err != nil {
		return Result{}, &Error{422, "invalid to address"}
	}
	if in.Subject == "" || (in.HTML == "" && in.Text == "") {
		return Result{}, &Error{422, "subject and html or text are required"}
	}
	// Validate ingress input that the delivery layer would otherwise only catch
	// at send time (see delivery.BuildMessage), which would leave a queued email
	// that can never send. Reject it immediately instead.
	if err := delivery.ValidateHeaderValue("Subject", in.Subject); err != nil {
		return Result{}, &Error{422, "invalid subject: " + err.Error()}
	}
	if in.ReplyTo != "" {
		if _, err := mail.ParseAddress(in.ReplyTo); err != nil {
			return Result{}, &Error{422, "invalid reply_to address"}
		}
	}
	if err := delivery.ValidateHeaderValue("From", delivery.FormatAddress(from.Name, from.Address)); err != nil {
		return Result{}, &Error{422, "invalid from: " + err.Error()}
	}
	if err := delivery.ValidateHeaderValue("To", delivery.FormatAddress(to.Name, to.Address)); err != nil {
		return Result{}, &Error{422, "invalid to: " + err.Error()}
	}
	for name, value := range in.Headers {
		if err := delivery.ValidateHeader(name, value); err != nil {
			return Result{}, &Error{422, "invalid header: " + err.Error()}
		}
	}
	domain, err := st.GetDomain(domainID)
	if err != nil {
		return Result{}, &Error{500, "internal error"}
	}
	fromDomain := from.Address[strings.LastIndex(from.Address, "@")+1:]
	if !strings.EqualFold(fromDomain, domain.Name) {
		return Result{}, &Error{422, "from address must be on domain " + domain.Name}
	}
	if !domain.Verified() {
		return Result{}, &Error{403, "domain " + domain.Name + " is not verified; complete DNS setup in the doevoe admin before sending"}
	}

	if in.IdempotencyKey != "" {
		if existing, err := st.FindByIdempotencyKey(apiKeyID, in.IdempotencyKey); err == nil && existing != nil {
			return Result{ID: existing.ID, Status: existing.Status, Replay: true}, nil
		}
	}

	headersJSON := "{}"
	if len(in.Headers) > 0 {
		hb, _ := json.Marshal(in.Headers)
		headersJSON = string(hb)
	}
	id, status, replay, err := enqueueOrReplay(st, &store.Email{
		APIKeyID: apiKeyID, DomainID: domain.ID,
		From: from.Address, To: to.Address, FromName: from.Name, ToName: to.Name, ReplyTo: in.ReplyTo,
		Subject: in.Subject, BodyHTML: in.HTML, BodyText: in.Text,
		HeadersJSON: headersJSON, IdempotencyKey: in.IdempotencyKey,
	})
	if err != nil {
		return Result{}, &Error{500, "enqueue failed"}
	}
	return Result{ID: id, Status: status, Replay: replay}, nil
}

// enqueueOrReplay inserts e via store.EnqueueEmail. A caller-supplied
// Idempotency-Key is already checked once by Send before this is
// called (FindByIdempotencyKey), but that check-then-insert is not atomic:
// a racing duplicate request can insert the same (api_key_id,
// idempotency_key) pair in between, and the partial unique index
// idx_emails_idem then causes this insert to fail. Rather than surface that
// as a bare 500 for what is really a successful, idempotent replay, this
// re-checks FindByIdempotencyKey on insert failure and, if a matching row
// now exists, returns it as a replay (200) instead of an error. If no
// matching row is found, or no idempotency key was supplied, the original
// insert error is returned unchanged.
func enqueueOrReplay(st *store.Store, e *store.Email) (id int64, status string, replay bool, err error) {
	id, err = st.EnqueueEmail(e)
	if err == nil {
		return id, "queued", false, nil
	}
	if e.IdempotencyKey != "" {
		if existing, ferr := st.FindByIdempotencyKey(e.APIKeyID, e.IdempotencyKey); ferr == nil && existing != nil {
			return existing.ID, existing.Status, true, nil
		}
	}
	return 0, "", false, err
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/send/... -v`
Expected: PASS (all four tests).

- [ ] **Step 5: Refactor `internal/api/api.go` to call `send.Send`**

Replace the body of `postEmail` from the `mail.ParseAddress` call (line 78) through the final `writeJSON` (line 161), and delete `enqueueOrReplay` (lines 164–186) plus the now-unused imports (`errors` stays — it's used for `MaxBytesError`; remove `net/mail` and `doevoe/internal/delivery`; add `doevoe/internal/send`):

```go
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
```

- [ ] **Step 6: Run the full suite**

Run: `go vet ./... && go test ./...`
Expected: PASS — in particular every existing test in `internal/api` passes unchanged. If any api test fails, the extraction changed a message or ordering: fix `send.go`, not the test.

- [ ] **Step 7: Commit**

```bash
git add internal/send internal/api/api.go
git commit -m "Extract shared send pipeline into internal/send"
```

---

### Task 2: Extract `internal/domains` (create + verify with the indeterminate guard)

The indeterminate-DNS rule currently lives in **two** places (`admin.verifyDomain`, `main.recheckDNSLoop`); an MCP verify tool would be the third copy. Centralize it, plus the ~10-line domain-create glue.

**Files:**
- Create: `internal/domains/domains.go`
- Create: `internal/domains/domains_test.go`
- Modify: `internal/admin/admin.go:590-607` (`createDomain`) and `:625-647` (`verifyDomain`)
- Modify: `cmd/doevoe/main.go:130-156` (`recheckDNSLoop`)

**Interfaces:**
- Consumes: `dkimkeys.Generate`, `store.CreateDomain/SetDomainVerification`, `dnscheck.Result`.
- Produces (used by Task 5, `internal/admin`, `cmd/doevoe`):
  ```go
  package domains
  var ErrInvalidName = errors.New("invalid domain name")
  type CheckFunc func(context.Context, *store.Domain) dnscheck.Result
  func Create(st *store.Store, name string) (*store.Domain, error) // ErrInvalidName on bad input
  func Verify(ctx context.Context, st *store.Store, check CheckFunc, d *store.Domain) (res dnscheck.Result, persisted bool, err error)
  ```

- [ ] **Step 1: Write the failing test**

`internal/domains/domains_test.go`:

```go
package domains

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"doevoe/internal/dnscheck"
	"doevoe/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCreateNormalizesAndGeneratesKey(t *testing.T) {
	s := openStore(t)
	d, err := Create(s, "  Example.COM ")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "example.com" || d.DKIMSelector != "mail1" || d.DKIMPrivateKey == "" {
		t.Fatalf("got %+v", d)
	}
}

func TestCreateRejectsInvalidName(t *testing.T) {
	s := openStore(t)
	for _, name := range []string{"", "a b.com", "a/b.com", "a@b.com"} {
		if _, err := Create(s, name); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("name %q: want ErrInvalidName, got %v", name, err)
		}
	}
}

func TestVerifyPersistsDeterminateResult(t *testing.T) {
	s := openStore(t)
	d, _ := Create(s, "example.com")
	check := func(context.Context, *store.Domain) dnscheck.Result {
		return dnscheck.Result{
			SPF:   dnscheck.RecordResult{OK: true},
			DKIM:  dnscheck.RecordResult{OK: true},
			DMARC: dnscheck.RecordResult{OK: true},
		}
	}
	res, persisted, err := Verify(context.Background(), s, check, d)
	if err != nil || !persisted || !res.AllOK() {
		t.Fatalf("res=%+v persisted=%v err=%v", res, persisted, err)
	}
	got, _ := s.GetDomain(d.ID)
	if !got.Verified() {
		t.Fatalf("domain not verified after persist: %+v", got)
	}
}

func TestVerifyNeverPersistsIndeterminate(t *testing.T) {
	s := openStore(t)
	d, _ := Create(s, "example.com")
	// Start verified: the whole point of the guard is that a transient
	// resolver blip must not flip a verified domain to unverified.
	s.SetDomainVerification(d.ID, true, true, true, store.Now())
	check := func(context.Context, *store.Domain) dnscheck.Result {
		return dnscheck.Result{Indeterminate: true}
	}
	_, persisted, err := Verify(context.Background(), s, check, d)
	if err != nil || persisted {
		t.Fatalf("persisted=%v err=%v", persisted, err)
	}
	got, _ := s.GetDomain(d.ID)
	if !got.Verified() {
		t.Fatal("indeterminate result flipped a verified domain")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/domains/... -v`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Write the implementation**

`internal/domains/domains.go`:

```go
// Package domains holds domain lifecycle logic shared by the admin UI, the
// hourly DNS recheck loop, and the MCP server: creation (with DKIM keypair
// generation) and verification (with the indeterminate-result guard).
package domains

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"doevoe/internal/dkimkeys"
	"doevoe/internal/dnscheck"
	"doevoe/internal/store"
)

var ErrInvalidName = errors.New("invalid domain name")

// CheckFunc matches the closure main.go builds around dnscheck.Check.
type CheckFunc func(context.Context, *store.Domain) dnscheck.Result

// Create lowercases and validates name, generates a fresh DKIM keypair, and
// inserts the domain with the default "mail1" selector. A duplicate name
// surfaces as the store's UNIQUE-constraint error.
func Create(st *store.Store, name string) (*store.Domain, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || strings.ContainsAny(name, " /@") {
		return nil, ErrInvalidName
	}
	priv, _, err := dkimkeys.Generate()
	if err != nil {
		return nil, err
	}
	return st.CreateDomain(name, "mail1", priv)
}

// Verify runs check and persists the result — unless it is indeterminate.
// A transient resolver failure is not a genuine "record missing" answer:
// persisting it would flip an already-verified domain to unverified (and
// fail-close its sends with 403) on a mere DNS blip, so the write is
// skipped and persisted is false. This is the single home of that rule;
// do not re-implement it at call sites.
func Verify(ctx context.Context, st *store.Store, check CheckFunc, d *store.Domain) (dnscheck.Result, bool, error) {
	res := check(ctx, d)
	if res.Indeterminate {
		slog.Warn("dns verification indeterminate; not persisting", "domain", d.Name)
		return res, false, nil
	}
	if err := st.SetDomainVerification(d.ID, res.SPF.OK, res.DKIM.OK, res.DMARC.OK, store.Now()); err != nil {
		return res, false, err
	}
	return res, true, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/domains/... -v`
Expected: PASS. (`TestCreate*` runs real RSA-2048 generation — a fraction of a second is normal.)

- [ ] **Step 5: Refactor the three call sites**

`internal/admin/admin.go` — `createDomain` becomes (add `"doevoe/internal/domains"` and `"errors"` to imports; drop the now-unused `dkimkeys` import **only if** `showDomain` no longer needs it — it does still use `dkimkeys.PublicB64FromPrivatePEM` and `dkimkeys.Records`, so the import stays):

```go
func (a *Admin) createDomain(w http.ResponseWriter, r *http.Request) {
	d, err := domains.Create(a.Store, r.FormValue("name"))
	if errors.Is(err, domains.ErrInvalidName) {
		http.Error(w, "invalid domain name", 422)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/domains/%d", d.ID), http.StatusSeeOther)
}
```

`verifyDomain` becomes (the indeterminate comment moves to `domains.Verify`; admin deliberately redirects regardless of outcome, matching today):

```go
func (a *Admin) verifyDomain(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := a.Store.GetDomain(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if a.CheckDomain == nil {
		http.Error(w, "verification not configured", http.StatusInternalServerError)
		return
	}
	domains.Verify(r.Context(), a.Store, domains.CheckFunc(a.CheckDomain), d)
	http.Redirect(w, r, fmt.Sprintf("/admin/domains/%d", d.ID), http.StatusSeeOther)
}
```

If `slog` is now unused in `admin.go`, remove the import.

`cmd/doevoe/main.go` — `recheckDNSLoop`'s inner loop body becomes (add `"doevoe/internal/domains"` import; the log line "dns recheck indeterminate" is replaced by `domains.Verify`'s "dns verification indeterminate" — an accepted, deliberate log-message change):

```go
for _, d := range domainList {
	domains.Verify(ctx, s, check, d)
}
```

(Rename the shadowing local `domains, err := s.ListDomains()` variable to `domainList` to avoid colliding with the package name.)

- [ ] **Step 6: Run the full suite**

Run: `go vet ./... && go test ./...`
Expected: PASS — `internal/admin` tests (including `domains_test.go`) pass unchanged.

- [ ] **Step 7: Commit**

```bash
git add internal/domains internal/admin/admin.go cmd/doevoe/main.go
git commit -m "Extract domain create/verify into internal/domains"
```

---

### Task 3: `internal/mcpserver` skeleton + read-only tools (`get_email_status`, `get_sending_stats`)

Adds the SDK dependency, the `Server` struct, the `MCP()` constructor, the test fixture (in-memory MCP client↔server), and the two pure pass-through tools.

**Files:**
- Modify: `go.mod` / `go.sum` (via `go get`)
- Create: `internal/mcpserver/mcpserver.go`
- Create: `internal/mcpserver/emails.go`
- Create: `internal/mcpserver/stats.go`
- Create: `internal/mcpserver/mcpserver_test.go`

**Interfaces:**
- Consumes: `store.GetEmail`, `store.SummaryStats/DailyVolume/DomainVolume/FailureReasons`, `store.FmtTime`.
- Produces (used by Tasks 4–7):
  ```go
  package mcpserver
  type Server struct {
      Store        *store.Store
      CheckDomain  func(context.Context, *store.Domain) dnscheck.Result
      // EgressIP/DMARCRua feed dkimkeys.Records; SystemDomain/Hostname feed
      // dkimkeys.SystemRecords, mirroring admin.showDomain (upstream added
      // these when the DMARC receiver landed — Records' 5th arg is now the
      // rua mailbox, not the admin email).
      EgressIP, DMARCRua, SystemDomain, Hostname string
      OnKeyCreated func(name, domainName string) // nil-safe, like admin's hooks
      OnKeyRevoked func(name, domainName string)
  }
  func (s *Server) MCP() *mcp.Server
  func boolPtr(b bool) *bool
  ```
  Test helpers (same file `mcpserver_test.go`, reused by later tasks' tests): `setup(t) (*Server, *store.Store, *mcp.ClientSession)`, `callTool(t, cs, name, args) map[string]any`, `callToolErr(t, cs, name, args) string`.

- [ ] **Step 1: Add the dependency**

```bash
go get github.com/modelcontextprotocol/go-sdk@v1.7.0
```

- [ ] **Step 2: Write the failing test**

`internal/mcpserver/mcpserver_test.go`:

```go
package mcpserver

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"doevoe/internal/dnscheck"
	"doevoe/internal/store"
)

// setup wires a Server to an in-memory MCP client session. CheckDomain is a
// stub returning all-OK; individual tests override srv.CheckDomain before
// the tool call they exercise (the tool handlers read it per call).
func setup(t *testing.T) (*Server, *store.Store, *mcp.ClientSession) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := &Server{
		Store:    st,
		EgressIP: "203.0.113.7",
		DMARCRua: "dmarc@mail.example.com",
		CheckDomain: func(context.Context, *store.Domain) dnscheck.Result {
			return dnscheck.Result{
				SPF:   dnscheck.RecordResult{OK: true},
				DKIM:  dnscheck.RecordResult{OK: true},
				DMARC: dnscheck.RecordResult{OK: true},
			}
		},
	}
	serverT, clientT := mcp.NewInMemoryTransports()
	ss, err := srv.MCP().Connect(context.Background(), serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0.0.0"}, nil)
	cs, err := client.Connect(context.Background(), clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return srv, st, cs
}

func toolText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		return ""
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content[0] is %T, want *mcp.TextContent", res.Content[0])
	}
	return tc.Text
}

// callTool invokes a tool and decodes its JSON text content, failing the
// test if the tool returned an error result.
func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) map[string]any {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("tool %s errored: %s", name, toolText(t, res))
	}
	out := map[string]any{}
	if err := json.Unmarshal([]byte(toolText(t, res)), &out); err != nil {
		t.Fatalf("tool %s output not JSON: %v", name, err)
	}
	return out
}

// callToolErr invokes a tool expecting an isError result and returns the
// error text.
func callToolErr(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if !res.IsError {
		t.Fatalf("tool %s: expected error result, got %s", name, toolText(t, res))
	}
	return toolText(t, res)
}

func TestGetEmailStatus(t *testing.T) {
	_, st, cs := setup(t)
	d, _ := st.CreateDomain("example.com", "mail1", "PEM")
	id, err := st.EnqueueEmail(&store.Email{
		DomainID: d.ID, From: "hi@example.com", To: "you@other.com",
		Subject: "s", BodyText: "b",
	})
	if err != nil {
		t.Fatal(err)
	}
	out := callTool(t, cs, "get_email_status", map[string]any{"id": id})
	if out["status"] != "queued" || int64(out["id"].(float64)) != id {
		t.Fatalf("got %v", out)
	}
}

func TestGetEmailStatusNotFound(t *testing.T) {
	_, _, cs := setup(t)
	callToolErr(t, cs, "get_email_status", map[string]any{"id": 999})
}

func TestGetSendingStats(t *testing.T) {
	_, st, cs := setup(t)
	d, _ := st.CreateDomain("example.com", "mail1", "PEM")
	st.EnqueueEmail(&store.Email{
		DomainID: d.ID, From: "hi@example.com", To: "you@other.com",
		Subject: "s", BodyText: "b",
	})
	out := callTool(t, cs, "get_sending_stats", map[string]any{"days": 7})
	sum, ok := out["summary"].(map[string]any)
	if !ok {
		t.Fatalf("no summary in %v", out)
	}
	if sum["total"].(float64) != 1 || sum["queued"].(float64) != 1 {
		t.Fatalf("got summary %v", sum)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/mcpserver/... -v`
Expected: FAIL — package/types undefined.

- [ ] **Step 4: Write the implementation**

`internal/mcpserver/mcpserver.go`:

```go
// Package mcpserver exposes doevoe's admin operations as Model Context
// Protocol tools. Everything here is admin-scoped: authentication (a
// shared bearer token, DOEVOE_MCP_TOKEN) happens at the HTTP layer in
// Handler, not per tool, and the tools are NOT limited to one domain the
// way API keys are — do not mount this handler without that token check.
package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"doevoe/internal/dnscheck"
	"doevoe/internal/store"
)

type Server struct {
	Store       *store.Store
	CheckDomain func(context.Context, *store.Domain) dnscheck.Result
	// EgressIP and DMARCRua parameterize dkimkeys.Records; SystemDomain and
	// Hostname parameterize dkimkeys.SystemRecords for the system domain,
	// mirroring admin.showDomain.
	EgressIP, DMARCRua, SystemDomain, Hostname string
	// Notification hooks, nil-safe (same contract as admin.Admin's).
	OnKeyCreated func(name, domainName string)
	OnKeyRevoked func(name, domainName string)
}

// MCP builds the SDK server with all tools registered. The SDK generates
// each tool's JSON schema from the typed input/output structs and handles
// protocol-version negotiation, so no wire-level code lives in this package.
func (s *Server) MCP() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "doevoe",
		Title:   "doevoe transactional email",
		Version: "1.0.0",
	}, nil)
	s.addEmailTools(srv)
	s.addStatsTool(srv)
	return srv
}

func boolPtr(b bool) *bool { return &b }
```

`internal/mcpserver/emails.go` (Task 4 adds `send_email` to this file and renames nothing):

```go
package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type emailStatusInput struct {
	ID int64 `json:"id" jsonschema:"the email id returned by send_email"`
}

type emailStatusOutput struct {
	ID        int64  `json:"id"`
	Status    string `json:"status"`
	Attempts  int    `json:"attempts"`
	LastError string `json:"last_error,omitempty"`
	CreatedAt string `json:"created_at"`
	SentAt    string `json:"sent_at,omitempty"`
}

func (s *Server) addEmailTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_email_status",
		Description: "Look up the delivery status of an email by id.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: boolPtr(false),
		},
	}, s.getEmailStatus)
}

func (s *Server) getEmailStatus(ctx context.Context, req *mcp.CallToolRequest, in emailStatusInput) (*mcp.CallToolResult, emailStatusOutput, error) {
	e, err := s.Store.GetEmail(in.ID)
	if err != nil {
		return nil, emailStatusOutput{}, fmt.Errorf("email %d not found", in.ID)
	}
	return nil, emailStatusOutput{
		ID: e.ID, Status: e.Status, Attempts: e.Attempts,
		LastError: e.LastError, CreatedAt: e.CreatedAt, SentAt: e.SentAt,
	}, nil
}
```

`internal/mcpserver/stats.go`:

```go
package mcpserver

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"doevoe/internal/store"
)

type statsInput struct {
	Days int `json:"days,omitempty" jsonschema:"how many days back to aggregate (default 30, max 365)"`
}

// Local mirrors of the store's stats types: the store structs carry no json
// tags, and the MCP output schema should not silently change if they gain
// some.
type statsSummary struct {
	Sent        int     `json:"sent"`
	Failed      int     `json:"failed"`
	Queued      int     `json:"queued"`
	Canceled    int     `json:"canceled"`
	Total       int     `json:"total"`
	SuccessRate float64 `json:"success_rate"`
}

type statsDay struct {
	Date   string `json:"date"`
	Sent   int    `json:"sent"`
	Failed int    `json:"failed"`
}

type statsDomain struct {
	Domain string `json:"domain"`
	Sent   int    `json:"sent"`
	Failed int    `json:"failed"`
}

type statsReason struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type statsOutput struct {
	Days           int           `json:"days"`
	Summary        statsSummary  `json:"summary"`
	Daily          []statsDay    `json:"daily"`
	Domains        []statsDomain `json:"domains"`
	FailureReasons []statsReason `json:"top_failure_reasons"`
}

func (s *Server) addStatsTool(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_sending_stats",
		Description: "Aggregate sending statistics over the last N days: totals by status, daily volume, per-domain volume, and top failure reasons.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: boolPtr(false),
		},
	}, s.getSendingStats)
}

func (s *Server) getSendingStats(ctx context.Context, req *mcp.CallToolRequest, in statsInput) (*mcp.CallToolResult, statsOutput, error) {
	days := in.Days
	if days <= 0 {
		days = 30
	}
	if days > 365 {
		days = 365
	}
	now := time.Now().UTC()
	// Upper bound is tomorrow, not now: the store ranges are half-open
	// [from, to) on RFC3339 strings, and "now" would exclude emails
	// created within the current second.
	from := store.FmtTime(now.AddDate(0, 0, -days))
	to := store.FmtTime(now.AddDate(0, 0, 1))

	sum, err := s.Store.SummaryStats(from, to)
	if err != nil {
		return nil, statsOutput{}, err
	}
	daily, err := s.Store.DailyVolume(from, to)
	if err != nil {
		return nil, statsOutput{}, err
	}
	domains, err := s.Store.DomainVolume(from, to)
	if err != nil {
		return nil, statsOutput{}, err
	}
	reasons, err := s.Store.FailureReasons(from, to, 8)
	if err != nil {
		return nil, statsOutput{}, err
	}

	out := statsOutput{
		Days: days,
		Summary: statsSummary{
			Sent: sum.Sent, Failed: sum.Failed, Queued: sum.Queued,
			Canceled: sum.Canceled, Total: sum.Total, SuccessRate: sum.SuccessRate,
		},
	}
	for _, d := range daily {
		out.Daily = append(out.Daily, statsDay{Date: d.Date, Sent: d.Sent, Failed: d.Failed})
	}
	for _, d := range domains {
		out.Domains = append(out.Domains, statsDomain{Domain: d.DomainName, Sent: d.Sent, Failed: d.Failed})
	}
	for _, r := range reasons {
		out.FailureReasons = append(out.FailureReasons, statsReason{Reason: r.Reason, Count: r.Count})
	}
	return nil, out, nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/mcpserver/... -v`
Expected: PASS (three tests).

- [ ] **Step 6: Run the full suite and commit**

Run: `go vet ./... && go test ./...`
Expected: PASS.

```bash
git add go.mod go.sum internal/mcpserver
git commit -m "Add internal/mcpserver with read-only status and stats tools"
```

---

### Task 4: `send_email` tool

**Files:**
- Modify: `internal/mcpserver/emails.go`
- Modify: `internal/mcpserver/mcpserver_test.go` (append tests)

**Interfaces:**
- Consumes: `send.Send(st, apiKeyID, domainID, in) (send.Result, *send.Error)` from Task 1; `store.GetDomainByName(name) (*store.Domain, error)` (returns `nil, nil` when absent).

- [ ] **Step 1: Write the failing tests** (append to `mcpserver_test.go`)

```go
func TestSendEmail(t *testing.T) {
	_, st, cs := setup(t)
	d, _ := st.CreateDomain("example.com", "mail1", "PEM")
	st.SetDomainVerification(d.ID, true, true, true, store.Now())
	out := callTool(t, cs, "send_email", map[string]any{
		"from": "Sender <hi@example.com>", "to": "you@other.com",
		"subject": "hello", "text": "body",
	})
	if out["status"] != "queued" {
		t.Fatalf("got %v", out)
	}
	e, err := st.GetEmail(int64(out["id"].(float64)))
	if err != nil || e.FromName != "Sender" || e.APIKeyID != 0 {
		t.Fatalf("stored email %+v err=%v", e, err)
	}
}

func TestSendEmailUnknownDomain(t *testing.T) {
	_, _, cs := setup(t)
	msg := callToolErr(t, cs, "send_email", map[string]any{
		"from": "hi@nowhere.com", "to": "you@other.com",
		"subject": "hello", "text": "body",
	})
	if msg == "" {
		t.Fatal("expected error text")
	}
}

func TestSendEmailUnverifiedDomainFailsClosed(t *testing.T) {
	_, st, cs := setup(t)
	st.CreateDomain("example.com", "mail1", "PEM") // not verified
	callToolErr(t, cs, "send_email", map[string]any{
		"from": "hi@example.com", "to": "you@other.com",
		"subject": "hello", "text": "body",
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/mcpserver/... -run TestSendEmail -v`
Expected: FAIL — tool `send_email` not found.

- [ ] **Step 3: Implement** (append to `emails.go`; add imports `"net/mail"`, `"strings"`, `"doevoe/internal/send"`)

```go
type sendEmailInput struct {
	From           string            `json:"from" jsonschema:"sender address on a domain registered and verified in doevoe; display-name form \"Name <addr@domain>\" is preserved"`
	To             string            `json:"to" jsonschema:"recipient address"`
	Subject        string            `json:"subject"`
	HTML           string            `json:"html,omitempty" jsonschema:"HTML body; provide html and/or text"`
	Text           string            `json:"text,omitempty" jsonschema:"plain-text body; provide html and/or text"`
	ReplyTo        string            `json:"reply_to,omitempty"`
	Headers        map[string]string `json:"headers,omitempty" jsonschema:"extra headers; From/To/Subject/Date/Message-ID and other doevoe-set headers are rejected"`
	IdempotencyKey string            `json:"idempotency_key,omitempty" jsonschema:"dedupe key: repeating a call with the same key replays the original result instead of sending twice"`
}

type sendEmailOutput struct {
	ID     int64  `json:"id"`
	Status string `json:"status"`
	Replay bool   `json:"replay,omitempty" jsonschema:"true when this was an idempotent replay of an earlier send"`
}
```

In `addEmailTools`, register before `get_email_status`:

```go
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "send_email",
		Description: "Queue a real transactional email for delivery. The from-address domain must already be registered and DNS-verified in doevoe. This immediately queues a real email to a real recipient.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: boolPtr(false), // additive: queues a row, overwrites nothing
			IdempotentHint:  false,
			OpenWorldHint:   boolPtr(true), // delivers to arbitrary external mailboxes
		},
	}, s.sendEmail)
```

Handler:

```go
func (s *Server) sendEmail(ctx context.Context, req *mcp.CallToolRequest, in sendEmailInput) (*mcp.CallToolResult, sendEmailOutput, error) {
	// MCP is admin-scoped rather than key-scoped, so the sending domain is
	// derived from the from address instead of an API key. send.Send
	// re-validates the from/domain match and the verified requirement.
	addr, err := mail.ParseAddress(in.From)
	if err != nil {
		return nil, sendEmailOutput{}, fmt.Errorf("invalid from address")
	}
	name := addr.Address[strings.LastIndex(addr.Address, "@")+1:]
	d, err := s.Store.GetDomainByName(strings.ToLower(name))
	if err != nil {
		return nil, sendEmailOutput{}, err
	}
	if d == nil {
		return nil, sendEmailOutput{}, fmt.Errorf("domain %s is not registered in doevoe; create it with create_domain first", name)
	}
	res, serr := send.Send(s.Store, 0, d.ID, send.Input{
		From: in.From, To: in.To, Subject: in.Subject, HTML: in.HTML, Text: in.Text,
		ReplyTo: in.ReplyTo, Headers: in.Headers, IdempotencyKey: in.IdempotencyKey,
	})
	if serr != nil {
		return nil, sendEmailOutput{}, serr
	}
	return nil, sendEmailOutput{ID: res.ID, Status: res.Status, Replay: res.Replay}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/mcpserver/... -v`
Expected: PASS.

- [ ] **Step 5: Full suite + commit**

Run: `go vet ./... && go test ./...`

```bash
git add internal/mcpserver
git commit -m "MCP: send_email tool via shared send pipeline"
```

---

### Task 5: `create_domain` + `verify_domain` tools

**Files:**
- Create: `internal/mcpserver/domains.go`
- Modify: `internal/mcpserver/mcpserver.go` (register: add `s.addDomainTools(srv)` in `MCP()`)
- Modify: `internal/mcpserver/mcpserver_test.go` (append tests)

**Interfaces:**
- Consumes: `domains.Create/Verify/ErrInvalidName/CheckFunc` (Task 2), `dkimkeys.PublicB64FromPrivatePEM(pem) (string, error)`, `dkimkeys.Records(domain, selector, pubBase64, egressIP, adminEmail) []dkimkeys.Record` (`Record{Type, Host, Value, Note string}`), `store.GetDomainByName`.

- [ ] **Step 1: Write the failing tests** (append to `mcpserver_test.go`)

```go
func TestCreateDomainReturnsDNSRecords(t *testing.T) {
	_, st, cs := setup(t)
	out := callTool(t, cs, "create_domain", map[string]any{"name": "Example.com"})
	if out["name"] != "example.com" {
		t.Fatalf("got %v", out)
	}
	recs, ok := out["dns_records"].([]any)
	if !ok || len(recs) == 0 {
		t.Fatalf("no dns_records in %v", out)
	}
	if d, _ := st.GetDomainByName("example.com"); d == nil {
		t.Fatal("domain not stored")
	}
}

func TestCreateDomainDuplicate(t *testing.T) {
	_, st, cs := setup(t)
	st.CreateDomain("example.com", "mail1", "PEM")
	callToolErr(t, cs, "create_domain", map[string]any{"name": "example.com"})
}

func TestVerifyDomainPersists(t *testing.T) {
	_, st, cs := setup(t)
	callTool(t, cs, "create_domain", map[string]any{"name": "example.com"})
	out := callTool(t, cs, "verify_domain", map[string]any{"name": "example.com"})
	if out["verified"] != true || out["persisted"] != true {
		t.Fatalf("got %v", out)
	}
	d, _ := st.GetDomainByName("example.com")
	if !d.Verified() {
		t.Fatal("verification not persisted")
	}
}

func TestVerifyDomainIndeterminateNotPersisted(t *testing.T) {
	srv, st, cs := setup(t)
	callTool(t, cs, "create_domain", map[string]any{"name": "example.com"})
	d, _ := st.GetDomainByName("example.com")
	st.SetDomainVerification(d.ID, true, true, true, store.Now())
	srv.CheckDomain = func(context.Context, *store.Domain) dnscheck.Result {
		return dnscheck.Result{Indeterminate: true}
	}
	out := callTool(t, cs, "verify_domain", map[string]any{"name": "example.com"})
	if out["indeterminate"] != true || out["persisted"] != false {
		t.Fatalf("got %v", out)
	}
	d, _ = st.GetDomainByName("example.com")
	if !d.Verified() {
		t.Fatal("indeterminate result flipped a verified domain")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/mcpserver/... -run "TestCreateDomain|TestVerifyDomain" -v`
Expected: FAIL — tools not found.

- [ ] **Step 3: Implement**

`internal/mcpserver/domains.go`:

```go
package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"doevoe/internal/dkimkeys"
	"doevoe/internal/domains"
	"doevoe/internal/store"
)

type createDomainInput struct {
	Name string `json:"name" jsonschema:"the domain to send from, e.g. example.com"`
}

type dnsRecord struct {
	Type  string `json:"type"`
	Host  string `json:"host"`
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
}

type createDomainOutput struct {
	ID      int64       `json:"id"`
	Name    string      `json:"name"`
	Records []dnsRecord `json:"dns_records" jsonschema:"the DNS records to add at the domain's DNS provider before verify_domain can pass"`
}

type verifyDomainInput struct {
	Name string `json:"name" jsonschema:"a domain previously created with create_domain"`
}

type recordCheck struct {
	OK       bool   `json:"ok"`
	Found    string `json:"found,omitempty"`
	Expected string `json:"expected,omitempty"`
}

type verifyDomainOutput struct {
	Name          string      `json:"name"`
	Verified      bool        `json:"verified"`
	Indeterminate bool        `json:"indeterminate" jsonschema:"true when a DNS lookup failed transiently; the result was not persisted, retry later"`
	Persisted     bool        `json:"persisted"`
	SPF           recordCheck `json:"spf"`
	DKIM          recordCheck `json:"dkim"`
	DMARC         recordCheck `json:"dmarc"`
}

func (s *Server) addDomainTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "create_domain",
		Description: "Register a sending domain: generates a DKIM keypair and returns the SPF/DKIM/DMARC DNS records to add at the DNS provider. Run verify_domain after the records are in place.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: boolPtr(false),
			IdempotentHint:  false,
			OpenWorldHint:   boolPtr(false),
		},
	}, s.createDomain)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "verify_domain",
		Description: "Check a domain's SPF, DKIM, and DMARC DNS records against the expected values and persist the result. Sending is only allowed from fully verified domains.",
		Annotations: &mcp.ToolAnnotations{
			IdempotentHint: true,
			OpenWorldHint:  boolPtr(false),
		},
	}, s.verifyDomain)
}

func (s *Server) createDomain(ctx context.Context, req *mcp.CallToolRequest, in createDomainInput) (*mcp.CallToolResult, createDomainOutput, error) {
	name := strings.ToLower(strings.TrimSpace(in.Name))
	// Pre-check for a friendly message; the UNIQUE index on domains.name
	// still backstops a race.
	if existing, err := s.Store.GetDomainByName(name); err != nil {
		return nil, createDomainOutput{}, err
	} else if existing != nil {
		return nil, createDomainOutput{}, fmt.Errorf("domain %s already exists (id %d)", name, existing.ID)
	}
	d, err := domains.Create(s.Store, in.Name)
	if err != nil {
		return nil, createDomainOutput{}, err
	}
	out, err := s.domainRecords(d)
	if err != nil {
		return nil, createDomainOutput{}, err
	}
	return nil, out, nil
}

func (s *Server) domainRecords(d *store.Domain) (createDomainOutput, error) {
	pub, err := dkimkeys.PublicB64FromPrivatePEM(d.DKIMPrivateKey)
	if err != nil {
		return createDomainOutput{}, err
	}
	records := dkimkeys.Records(d.Name, d.DKIMSelector, pub, s.EgressIP, s.DMARCRua)
	// Same rule as admin.showDomain: the system domain additionally needs
	// the one-time MX/TXT records that make the built-in DMARC report
	// receiver reachable.
	if d.Name == s.SystemDomain {
		records = append(records, dkimkeys.SystemRecords(s.SystemDomain, s.Hostname)...)
	}
	out := createDomainOutput{ID: d.ID, Name: d.Name}
	for _, r := range records {
		out.Records = append(out.Records, dnsRecord{Type: r.Type, Host: r.Host, Value: r.Value, Note: r.Note})
	}
	return out, nil
}

func (s *Server) verifyDomain(ctx context.Context, req *mcp.CallToolRequest, in verifyDomainInput) (*mcp.CallToolResult, verifyDomainOutput, error) {
	name := strings.ToLower(strings.TrimSpace(in.Name))
	d, err := s.Store.GetDomainByName(name)
	if err != nil {
		return nil, verifyDomainOutput{}, err
	}
	if d == nil {
		return nil, verifyDomainOutput{}, fmt.Errorf("domain %s is not registered; create it with create_domain first", name)
	}
	res, persisted, err := domains.Verify(ctx, s.Store, domains.CheckFunc(s.CheckDomain), d)
	if err != nil {
		return nil, verifyDomainOutput{}, err
	}
	return nil, verifyDomainOutput{
		Name:          d.Name,
		Verified:      res.AllOK(),
		Indeterminate: res.Indeterminate,
		Persisted:     persisted,
		SPF:           recordCheck{OK: res.SPF.OK, Found: res.SPF.Found, Expected: res.SPF.Expected},
		DKIM:          recordCheck{OK: res.DKIM.OK, Found: res.DKIM.Found, Expected: res.DKIM.Expected},
		DMARC:         recordCheck{OK: res.DMARC.OK, Found: res.DMARC.Found, Expected: res.DMARC.Expected},
	}, nil
}
```

In `mcpserver.go`'s `MCP()`, add `s.addDomainTools(srv)` after `s.addEmailTools(srv)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/mcpserver/... -v`
Expected: PASS.

- [ ] **Step 5: Full suite + commit**

Run: `go vet ./... && go test ./...`

```bash
git add internal/mcpserver
git commit -m "MCP: create_domain and verify_domain tools"
```

---

### Task 6: `store.GetAPIKey` + `create_api_key` / `revoke_api_key` tools

**Files:**
- Modify: `internal/store/apikeys.go` (add `GetAPIKey`)
- Modify: `internal/store/apikeys_test.go` (append test)
- Create: `internal/mcpserver/keys.go`
- Modify: `internal/mcpserver/mcpserver.go` (register: add `s.addKeyTools(srv)` in `MCP()`)
- Modify: `internal/mcpserver/mcpserver_test.go` (append tests)

**Interfaces:**
- Consumes: `store.GenerateAPIKey() (token, hash string, err error)`, `store.CreateAPIKey(name, domainID, hash) (int64, error)`, `store.RevokeAPIKey(id) error`, `store.GetDomainByName`, `store.GetDomain`.
- Produces: `func (s *Store) GetAPIKey(id int64) (*APIKey, error)` — returns `nil, nil` when the id doesn't exist (matches `GetAPIKeyByHash`/`GetDomainByName` convention). Note it does **not** filter on `revoked`, unlike `GetAPIKeyByHash`: revoke needs to see the row either way.

- [ ] **Step 1: Write the failing store test** (append to `internal/store/apikeys_test.go`, following the file's existing style)

```go
func TestGetAPIKey(t *testing.T) {
	s := testStore(t) // existing helper in the store test suite
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	_, hash, _ := GenerateAPIKey()
	id, err := s.CreateAPIKey("k1", d.ID, hash)
	if err != nil {
		t.Fatal(err)
	}
	k, err := s.GetAPIKey(id)
	if err != nil || k == nil || k.Name != "k1" || k.DomainID != d.ID {
		t.Fatalf("got %+v err=%v", k, err)
	}
	if missing, err := s.GetAPIKey(9999); err != nil || missing != nil {
		t.Fatalf("want nil,nil for missing id, got %+v err=%v", missing, err)
	}
	// Revoked keys must still be visible by id (revoke tooling needs them).
	s.RevokeAPIKey(id)
	k, err = s.GetAPIKey(id)
	if err != nil || k == nil || !k.Revoked {
		t.Fatalf("revoked key: got %+v err=%v", k, err)
	}
}
```


- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/... -run TestGetAPIKey -v`
Expected: FAIL — `GetAPIKey` undefined.

- [ ] **Step 3: Implement `GetAPIKey`** (append to `internal/store/apikeys.go`)

```go
// GetAPIKey returns the key with the given id, or nil if it doesn't exist.
// Unlike GetAPIKeyByHash it does not filter on revoked: callers managing
// keys need to see revoked rows too.
func (s *Store) GetAPIKey(id int64) (*APIKey, error) {
	k := &APIKey{}
	err := s.db.QueryRow(`SELECT id, name, key_hash, domain_id, revoked, last_used_at, created_at
		FROM api_keys WHERE id=?`, id).
		Scan(&k.ID, &k.Name, &k.KeyHash, &k.DomainID, &k.Revoked, &k.LastUsedAt, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}
```

Run: `go test ./internal/store/... -run TestGetAPIKey -v` → PASS.

- [ ] **Step 4: Write the failing MCP tests** (append to `mcpserver_test.go`)

```go
func TestCreateAndRevokeAPIKey(t *testing.T) {
	srv, st, cs := setup(t)
	var created, revoked bool
	srv.OnKeyCreated = func(name, domainName string) { created = true }
	srv.OnKeyRevoked = func(name, domainName string) { revoked = true }
	st.CreateDomain("example.com", "mail1", "PEM")

	out := callTool(t, cs, "create_api_key", map[string]any{"name": "ci", "domain": "example.com"})
	token, _ := out["token"].(string)
	if !strings.HasPrefix(token, "dv_") {
		t.Fatalf("bad token %q", token)
	}
	if !created {
		t.Fatal("OnKeyCreated not fired")
	}
	if k, _ := st.GetAPIKeyByHash(store.HashAPIKey(token)); k == nil {
		t.Fatal("token does not authenticate")
	}

	id := int64(out["id"].(float64))
	callTool(t, cs, "revoke_api_key", map[string]any{"id": id})
	if !revoked {
		t.Fatal("OnKeyRevoked not fired")
	}
	if k, _ := st.GetAPIKeyByHash(store.HashAPIKey(token)); k != nil {
		t.Fatal("revoked token still authenticates")
	}
}

func TestCreateAPIKeyUnknownDomain(t *testing.T) {
	_, _, cs := setup(t)
	callToolErr(t, cs, "create_api_key", map[string]any{"name": "ci", "domain": "nowhere.com"})
}

func TestRevokeAPIKeyUnknownID(t *testing.T) {
	_, _, cs := setup(t)
	callToolErr(t, cs, "revoke_api_key", map[string]any{"id": 424242})
}
```

(Add `"strings"` to the test file's imports.)

- [ ] **Step 5: Run tests to verify they fail**

Run: `go test ./internal/mcpserver/... -run "APIKey" -v`
Expected: FAIL — tools not found.

- [ ] **Step 6: Implement**

`internal/mcpserver/keys.go`:

```go
package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"doevoe/internal/store"
)

type createKeyInput struct {
	Name   string `json:"name" jsonschema:"a label for the key, e.g. the app that will use it"`
	Domain string `json:"domain" jsonschema:"the registered domain this key may send from"`
}

type createKeyOutput struct {
	ID    int64  `json:"id"`
	Token string `json:"token" jsonschema:"the bearer token for the API; it is shown only this once and stored hashed, so save it now"`
}

type revokeKeyInput struct {
	ID int64 `json:"id" jsonschema:"the api key id to revoke"`
}

type revokeKeyOutput struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Domain  string `json:"domain"`
	Revoked bool   `json:"revoked"`
}

func (s *Server) addKeyTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "create_api_key",
		Description: "Create an API key scoped to one sending domain. The returned token is a live sending credential shown exactly once.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: boolPtr(false),
			IdempotentHint:  false,
			OpenWorldHint:   boolPtr(false),
		},
	}, s.createAPIKey)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "revoke_api_key",
		Description: "Revoke an API key by id. Requests using the key stop authenticating immediately; this cannot be undone.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: boolPtr(true),
			IdempotentHint:  true,
			OpenWorldHint:   boolPtr(false),
		},
	}, s.revokeAPIKey)
}

func (s *Server) createAPIKey(ctx context.Context, req *mcp.CallToolRequest, in createKeyInput) (*mcp.CallToolResult, createKeyOutput, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, createKeyOutput{}, fmt.Errorf("name is required")
	}
	d, err := s.Store.GetDomainByName(strings.ToLower(strings.TrimSpace(in.Domain)))
	if err != nil {
		return nil, createKeyOutput{}, err
	}
	if d == nil {
		return nil, createKeyOutput{}, fmt.Errorf("domain %s is not registered; create it with create_domain first", in.Domain)
	}
	token, hash, err := store.GenerateAPIKey()
	if err != nil {
		return nil, createKeyOutput{}, err
	}
	id, err := s.Store.CreateAPIKey(in.Name, d.ID, hash)
	if err != nil {
		return nil, createKeyOutput{}, err
	}
	if s.OnKeyCreated != nil {
		s.OnKeyCreated(in.Name, d.Name)
	}
	return nil, createKeyOutput{ID: id, Token: token}, nil
}

func (s *Server) revokeAPIKey(ctx context.Context, req *mcp.CallToolRequest, in revokeKeyInput) (*mcp.CallToolResult, revokeKeyOutput, error) {
	k, err := s.Store.GetAPIKey(in.ID)
	if err != nil {
		return nil, revokeKeyOutput{}, err
	}
	if k == nil {
		return nil, revokeKeyOutput{}, fmt.Errorf("api key %d not found", in.ID)
	}
	var domainName string
	if d, err := s.Store.GetDomain(k.DomainID); err == nil {
		domainName = d.Name
	}
	if err := s.Store.RevokeAPIKey(k.ID); err != nil {
		return nil, revokeKeyOutput{}, err
	}
	if s.OnKeyRevoked != nil {
		s.OnKeyRevoked(k.Name, domainName)
	}
	return nil, revokeKeyOutput{ID: k.ID, Name: k.Name, Domain: domainName, Revoked: true}, nil
}
```

In `mcpserver.go`'s `MCP()`, add `s.addKeyTools(srv)` after `s.addDomainTools(srv)`.

- [ ] **Step 7: Run tests, full suite, commit**

Run: `go test ./internal/mcpserver/... ./internal/store/... -v` then `go vet ./... && go test ./...`
Expected: PASS.

```bash
git add internal/store internal/mcpserver
git commit -m "MCP: create_api_key and revoke_api_key tools; store.GetAPIKey"
```

---

### Task 7: Config, bearer auth, HTTP handler, wiring, docs

**Files:**
- Modify: `internal/config/config.go` (add `MCPToken`)
- Modify: `internal/config/config_test.go` (append test)
- Create: `internal/mcpserver/handler.go`
- Create: `internal/mcpserver/handler_test.go`
- Modify: `cmd/doevoe/main.go` (mount)
- Modify: `.env.example`, `README.md`

**Interfaces:**
- Produces: `config.Config.MCPToken string` (optional, no default); `func Handler(s *Server, token string) http.Handler`.

- [ ] **Step 1: Write the failing config test** (append to `internal/config/config_test.go`; `setRequired(t)` is the file's existing helper that sets the five required env vars)

```go
func TestMCPTokenOptional(t *testing.T) {
	setRequired(t) // existing helper in config_test.go
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.MCPToken != "" {
		t.Fatalf("want empty default, got %q", c.MCPToken)
	}
	t.Setenv("DOEVOE_MCP_TOKEN", "sekrit")
	c, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.MCPToken != "sekrit" {
		t.Fatalf("got %q", c.MCPToken)
	}
}
```

- [ ] **Step 2: Implement config**

In `internal/config/config.go`: add `MCPToken string` to the `Config` struct (after `PublicURL`), and in `Load()` add `MCPToken: os.Getenv("DOEVOE_MCP_TOKEN"),` to the struct literal. It is deliberately **not** in the required-vars map: unset means the MCP endpoint is never mounted.

Run: `go test ./internal/config/... -v` → PASS.

- [ ] **Step 3: Write the failing handler test**

`internal/mcpserver/handler_test.go`:

```go
package mcpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBearerAuth(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // sentinel: request got through
	})
	h := bearerAuth("sekrit", inner)

	cases := []struct {
		name, header string
		want         int
	}{
		{"no header", "", 401},
		{"wrong scheme", "Basic sekrit", 401},
		{"wrong token", "Bearer nope", 401},
		{"correct", "Bearer sekrit", http.StatusTeapot},
	}
	for _, c := range cases {
		req := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
		if c.header != "" {
			req.Header.Set("Authorization", c.header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: got %d want %d", c.name, rec.Code, c.want)
		}
	}
}

func TestBearerAuthEmptyConfiguredTokenRejectsAll(t *testing.T) {
	// Defense in depth: main only mounts the handler when a token is set,
	// but an empty token must never mean "allow everything".
	h := bearerAuth("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("got %d want 401", rec.Code)
	}
}

func TestHandlerRejectsUnauthenticated(t *testing.T) {
	srv, _, _ := setup(t)
	ts := httptest.NewServer(Handler(srv, "sekrit"))
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("unauthenticated: got %d want 401", resp.StatusCode)
	}

	req, _ := http.NewRequest("POST", ts.URL, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer sekrit")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// The SDK decides what a bare "{}" POST means per negotiated protocol
	// revision; all that matters here is that auth passed.
	if resp.StatusCode == 401 {
		t.Fatal("authenticated request was rejected by bearerAuth")
	}
}
```

Run: `go test ./internal/mcpserver/... -run "Bearer|Handler" -v`
Expected: FAIL — `bearerAuth`/`Handler` undefined.

- [ ] **Step 4: Implement the handler**

`internal/mcpserver/handler.go`:

```go
package mcpserver

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Handler returns the HTTP handler for the MCP endpoint: the SDK's
// Streamable HTTP transport wrapped in bearer-token auth. One *mcp.Server
// is shared across requests; the SDK manages per-connection protocol
// negotiation and any session state internally.
func Handler(s *Server, token string) http.Handler {
	m := s.MCP()
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return m }, nil)
	return bearerAuth(token, h)
}

// bearerAuth admits only requests carrying "Authorization: Bearer <token>".
// An empty configured token rejects everything rather than allowing
// everything: main only mounts the endpoint when a token is set, but this
// must stay fail-closed even if that changes.
func bearerAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		got := strings.TrimPrefix(header, "Bearer ")
		if token == "" || got == "" || got == header ||
			subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```

Run: `go test ./internal/mcpserver/... -v` → PASS.

- [ ] **Step 5: Wire into `cmd/doevoe/main.go`**

Add import `"doevoe/internal/mcpserver"`. After the `adm.Routes(mux)` line (main.go:71), insert:

```go
	if cfg.MCPToken != "" {
		m := &mcpserver.Server{
			Store: s, CheckDomain: checkDomain,
			EgressIP: cfg.EgressIP, DMARCRua: reportAddr,
			SystemDomain: systemDomain, Hostname: cfg.Hostname,
			OnKeyCreated: notifier.KeyCreated, OnKeyRevoked: notifier.KeyRevoked,
		}
		mux.Handle("/mcp", mcpserver.Handler(m, cfg.MCPToken))
		slog.Info("mcp endpoint enabled", "path", "/mcp")
	}
```

- [ ] **Step 6: Update docs**

`.env.example` — append:

```
# Optional: expose an MCP (Model Context Protocol) server at POST /mcp so
# AI agents can send email, manage domains/keys, and read stats. The token
# is an admin-level credential (Authorization: Bearer <token>); generate a
# long random value, e.g. `openssl rand -hex 32`. Unset = MCP disabled.
#DOEVOE_MCP_TOKEN=
```

`README.md` — add this row to the configuration table (after the `DOEVOE_FAILURE_RATE_THRESHOLD` row):

```
| `DOEVOE_MCP_TOKEN` | no | — (disabled) | Bearer token for the MCP server at `/mcp`; unset disables the endpoint entirely. Admin-level credential: MCP tools can create domains and API keys and send from any verified domain |
```

And add a short section (place it after the HTTP API section, before Configuration):

```markdown
## MCP server

Set `DOEVOE_MCP_TOKEN` and doevoe serves a [Model Context Protocol](https://modelcontextprotocol.io)
endpoint at `POST /mcp` (Streamable HTTP transport, official Go SDK — protocol
versions 2024-11-05 through 2026-07-28 negotiated per connection). Authentication
is `Authorization: Bearer $DOEVOE_MCP_TOKEN`; the token is admin-scoped, unlike
domain-scoped API keys, so treat it like the admin password.

Tools: `send_email`, `get_email_status`, `create_domain` (returns the DNS
records to add), `verify_domain`, `create_api_key` (returns the token once),
`revoke_api_key`, `get_sending_stats`.
```

- [ ] **Step 7: Full suite, build, commit**

Run: `go vet ./... && go test ./... && go build ./...`
Expected: PASS.

```bash
git add internal/config internal/mcpserver cmd/doevoe/main.go .env.example README.md
git commit -m "MCP: mount /mcp behind DOEVOE_MCP_TOKEN; document"
```

---

## Verification checklist (after all tasks)

- [ ] `go vet ./... && go test ./...` green (CI parity).
- [ ] `internal/api` and `internal/admin` test files were not modified by any task (regression net intact).
- [ ] Grep check — the indeterminate-persist rule exists in exactly one place: `grep -rn "Indeterminate" internal/ cmd/ | grep -v _test.go | grep -v dnscheck` should show only `internal/domains/domains.go` (plus the main.go closure that *returns* an indeterminate result, which is fine — it decides indeterminacy, it doesn't persist).
- [ ] Manual smoke test (optional, needs env vars): run with `DOEVOE_MCP_TOKEN=test go run ./cmd/doevoe`, then `curl -s -X POST localhost:8080/mcp -H "Authorization: Bearer wrong" -d '{}'` → 401, and with the right token → a non-401 SDK response.
