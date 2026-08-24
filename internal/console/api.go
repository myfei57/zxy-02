package console

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"certbridge/internal/audit"
	"certbridge/internal/crl"
	"certbridge/internal/enrollment"
	"certbridge/internal/issuer"
	"certbridge/internal/keyarch"
	"certbridge/internal/revocation"
	"certbridge/internal/store"
	"certbridge/internal/verify"
)

// API is the HTTP surface of the service.
type API struct {
	state   *store.State
	issuer  *issuer.Issuer
	revoker *revocation.Service
	crl     *crl.Service
	verify  *verify.Verifier
	keyarch *keyarch.Archiver
	windows *enrollment.WindowManager
	audit   *audit.Sink
	pool    *issuer.SerialPool
}

// NewAPI wires the console API.
func NewAPI(
	state *store.State,
	issuer *issuer.Issuer,
	revoker *revocation.Service,
	crl *crl.Service,
	verifier *verify.Verifier,
	archiver *keyarch.Archiver,
	windows *enrollment.WindowManager,
	sink *audit.Sink,
	pool *issuer.SerialPool,
) *API {
	return &API{
		state:   state,
		issuer:  issuer,
		revoker: revoker,
		crl:     crl,
		verify:  verifier,
		keyarch: archiver,
		windows: windows,
		audit:   sink,
		pool:    pool,
	}
}

// Router builds the full HTTP route tree.
func (a *API) Router() http.Handler {
	r := chi.NewRouter()
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	r.Get("/api/certificates", a.listCertificates)
	r.Get("/api/requests", a.listRequests)
	r.Get("/api/revocations", a.listRevocations)
	r.Get("/api/crl", a.getCrl)
	r.Get("/api/crl/encoded", a.getCrlEncoded)
	r.Get("/api/revocation-reasons", a.revocationReasons)
	r.Get("/api/verify/{id}", a.verifyCert)
	r.Get("/api/audit", a.listAudit)
	r.Get("/api/metrics", a.metrics)
	r.Get("/api/certificates/{id}/pem", a.certPem)
	r.Get("/api/certificates/{id}/window", a.certWindow)
	r.Get("/api/windows", a.listWindows)
	r.Get("/api/crl/stats", a.crlStats)
	r.Get("/api/revocations/summary", a.revocationSummary)
	r.Get("/api/keys", a.listKeys)
	r.Get("/api/requests/summary", a.requestSummary)
	r.Get("/api/serials", a.serialStats)
	r.Get("/api/verify/stats", a.verifyStats)
	r.Post("/api/audit/trim", a.trimAudit)
	r.Post("/api/requests", a.submitRequest)
	r.Post("/api/requests/{id}/approve", a.approveRequest)
	r.Post("/api/requests/{id}/reject", a.rejectRequest)
	r.Post("/api/requests/{id}/issue", a.issueRequest)
	r.Post("/api/certificates/{id}/revoke", a.revokeCert)
	r.Post("/api/certificates/{id}/renew", a.renewCert)
	r.Post("/api/certificates/{id}/archive", a.archiveKey)
	r.Get("/", a.index)
	r.Get("/console/certificates", a.certsPage)
	r.Get("/console/requests", a.requestsPage)
	r.Get("/console/revocations", a.revocationsPage)
	r.Get("/console/crl", a.crlPage)
	return r
}

func (a *API) listCertificates(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	subject := r.URL.Query().Get("subject")
	generation := r.URL.Query().Get("generation")
	var out []*store.Certificate
	if status != "" {
		out = a.state.CertificatesByStatus(status)
	} else if subject != "" {
		out = a.state.CertificatesBySubject(subject)
	} else if generation != "" {
		out = a.state.CertificatesByGeneration(parseInt(generation))
	} else {
		out = a.state.ListCertificates()
	}
	writeJSON(w, out)
}

func (a *API) listRequests(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status != "" {
		writeJSON(w, a.state.RequestsByStatus(status))
		return
	}
	writeJSON(w, a.state.ListRequests())
}

func (a *API) listRevocations(w http.ResponseWriter, r *http.Request) {
	reason := r.URL.Query().Get("reason")
	generation := r.URL.Query().Get("generation")
	entries := a.state.Revocations()
	if reason != "" {
		entries = a.state.RevocationsByReason(reason)
	} else if generation != "" {
		entries = a.state.RevocationsByGeneration(parseInt(generation))
	}
	writeJSON(w, map[string]any{
		"entries": entries,
		"reasons": revocation.ListByReason(),
	})
}

func (a *API) getCrl(w http.ResponseWriter, r *http.Request) {
	serial := r.URL.Query().Get("serial")
	entries := a.crl.Entries()
	selected := entries
	if serial != "" {
		if entry, ok := crl.FindEntry(entries, parseInt(serial)); ok {
			selected = []store.RevocationEntry{entry}
		} else {
			selected = nil
		}
	}
	writeJSON(w, map[string]any{
		"version": a.crl.Version(),
		"entries": selected,
	})
}

func (a *API) getCrlEncoded(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"version": a.crl.Version(),
		"encoded": crl.EncodeEntries(a.crl.Entries()),
	})
}

func (a *API) revocationReasons(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, revocation.ListByReason())
}

func (a *API) listAudit(w http.ResponseWriter, r *http.Request) {
	event := r.URL.Query().Get("event")
	entries := a.audit.All()
	if event != "" {
		entries = a.state.AuditByEvent(event)
	}
	writeJSON(w, map[string]any{
		"summary": a.audit.Summary(),
		"entries": entries,
		"count":   a.state.AuditCount(),
	})
}

func (a *API) metrics(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"certificates":  CountCertificates(a.state),
		"active":        ActiveCount(a.state),
		"revocations":   CountRevocations(a.state),
		"revoked_total": revocation.TotalRevoked(a.state),
		"expired":       ExpiredCount(a.state),
		"revoked":       RevokedCount(a.state),
		"requests":      RequestCount(a.state),
	})
}

func (a *API) certPem(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cert, ok := a.state.Certificate(id)
	if !ok {
		writeJSONStatus(w, http.StatusNotFound, map[string]string{"error": "certificate not found"})
		return
	}
	writeJSON(w, map[string]string{
		"id":          id,
		"fingerprint": issuer.CertificateFingerprint(cert),
		"pem":         issuer.EncodeCertificate(cert),
	})
}

func (a *API) certWindow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	writeJSON(w, map[string]any{
		"certificate_id": id,
		"open":           a.windows.IsOpen(id),
		"remaining":      a.windows.Remaining(id),
	})
}

func (a *API) listWindows(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, a.state.Windows())
}

func (a *API) crlStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, crl.ComputeStats(a.state, a.crl.Version()))
}

func (a *API) revocationSummary(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, revocation.Summary(a.state.Revocations()))
}

func (a *API) listKeys(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"records": a.state.KeyRecords(),
		"count":   a.state.KeyCount(),
	})
}

func (a *API) requestSummary(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"summary": enrollment.QueueSummary(a.state),
		"pending": enrollment.PendingRequests(a.state),
	})
}

func (a *API) serialStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, a.pool.Stats())
}

func (a *API) verifyStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, a.verify.CacheStats())
}

func (a *API) trimAudit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Max int `json:"max"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Max <= 0 {
		body.Max = 1000
	}
	writeJSON(w, map[string]int{"removed": a.audit.Trim(body.Max)})
}

func (a *API) verifyCert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ok, status := a.verify.Verify(id)
	writeJSON(w, map[string]any{"certificate_id": id, "valid": ok, "status": status})
}

func (a *API) submitRequest(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	id, err := enrollment.Submit(a.state, data)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]string{"request_id": id})
}

func (a *API) approveRequest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := enrollment.Approve(a.state, id); err != nil {
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]string{"request_id": id, "status": "approved"})
}

func (a *API) rejectRequest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := enrollment.Reject(a.state, id); err != nil {
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]string{"request_id": id, "status": "rejected"})
}

func (a *API) issueRequest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cert, err := a.issuer.Issue(id)
	if err != nil {
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, cert)
}

func (a *API) revokeCert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	reason, err := revocation.NormalizeListedReason(body.Reason)
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := a.revoker.RevokeCertificate(id, reason); err != nil {
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]string{"certificate_id": id, "status": "revoked"})
}

func (a *API) renewCert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cert, err := a.windows.RenewCertificate(id, func(generation int64) (*store.Certificate, error) {
		current, ok := a.state.Certificate(id)
		if !ok {
			return nil, errors.New("unknown certificate")
		}
		snapshot := store.RequestSnapshot{Subject: current.Subject, SANs: current.SANs}
		return a.issuer.IssueFromSnapshot(snapshot, generation)
	})
	if err != nil {
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": fmt.Sprint(err)})
		return
	}
	a.windows.Close(id)
	writeJSON(w, cert)
}

func (a *API) archiveKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	material, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := a.keyarch.Archive(id, material); err != nil {
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]string{"certificate_id": id, "status": "archived"})
}

func writeJSON(w http.ResponseWriter, value any) {
	writeJSONStatus(w, http.StatusOK, value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func parseInt(value string) int64 {
	var out int64
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			break
		}
		out = out*10 + int64(ch-'0')
	}
	return out
}
