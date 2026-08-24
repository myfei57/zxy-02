package audit

import "errors"

// ErrKeyMaterialInAudit is returned when a caller tries to record key
// material in the audit trail.
var ErrKeyMaterialInAudit = errors.New("key material must never enter the audit path")
