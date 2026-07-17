// Package model contains persisted controller state and external DNSSEC models.
package model

import "time"

// Kind identifies a controller workflow family.
type Kind string

// Supported workflow kinds.
const (
	KindZSK    Kind = "zsk"
	KindKSK    Kind = "ksk"
	KindSplit  Kind = "split"
	KindEnroll Kind = "enroll"
)

// Phase identifies a persisted workflow state.
type Phase string

// Persisted workflow phases.
const (
	PhaseIdle              Phase = "idle"
	PhasePrepublish        Phase = "prepublish"
	PhaseWaitPublish       Phase = "wait_publish"
	PhaseActivateNew       Phase = "activate_new"
	PhaseWaitNewSignature  Phase = "wait_new_signature"
	PhaseDeactivateOld     Phase = "deactivate_old"
	PhaseParentRemove      Phase = "parent_remove"
	PhaseWaitParentRemove  Phase = "wait_parent_remove"
	PhaseWaitRetire        Phase = "wait_retire"
	PhaseDeleteOld         Phase = "delete_old"
	PhaseEnrollDiscovered  Phase = "enroll_discovered"
	PhaseEnrollWaitPublish Phase = "enroll_wait_publish"
	PhaseEnrollParentAdd   Phase = "enroll_parent_add"
	PhaseEnrollWaitParent  Phase = "enroll_wait_parent"
	PhaseBlocked           Phase = "blocked"
)

// Key describes a PowerDNS DNSSEC key without private material.
type Key struct {
	ID        int      `json:"id"`
	KeyType   string   `json:"keytype"`
	Active    bool     `json:"active"`
	Published bool     `json:"published"`
	DNSKEY    string   `json:"dnskey,omitempty"`
	DS        []string `json:"ds,omitempty"`
	Algorithm string   `json:"algorithm"`
	Bits      int      `json:"bits,omitempty"`
}

// RRSet describes a PowerDNS resource-record set.
type RRSet struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	TTL     uint32 `json:"ttl"`
	Records []struct {
		Content  string `json:"content"`
		Disabled bool   `json:"disabled"`
	} `json:"records"`
}

// Zone describes a PowerDNS zone and its DNSSEC state.
type Zone struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Kind   string  `json:"kind"`
	DNSSEC bool    `json:"dnssec"`
	RRsets []RRSet `json:"rrsets,omitempty"`
}

// DNSSECData contains public DNSKEY material accepted by the registrar.
type DNSSECData struct {
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	PublicKey string `json:"publicKey"`
}

// Workflow contains the restart-safe state for one zone and rotation kind.
type Workflow struct {
	Zone                    string    `json:"zone"`
	ZoneID                  string    `json:"zoneId,omitempty"`
	Kind                    Kind      `json:"kind"`
	Phase                   Phase     `json:"phase"`
	OldKeyID                int       `json:"oldKeyId,omitempty"`
	NewKeyID                int       `json:"newKeyId,omitempty"`
	NewZSKID                int       `json:"newZskId,omitempty"`
	NewKeyCreateAttemptedAt time.Time `json:"newKeyCreateAttemptedAt,omitempty"`
	NewZSKCreateAttemptedAt time.Time `json:"newZskCreateAttemptedAt,omitempty"`
	PhaseStartedAt          time.Time `json:"phaseStartedAt,omitempty"`
	NextActionAt            time.Time `json:"nextActionAt,omitempty"`
	LastCompletedAt         time.Time `json:"lastCompletedAt,omitempty"`
	LastError               string    `json:"lastError,omitempty"`
	Attempts                int       `json:"attempts,omitempty"`
	Manual                  bool      `json:"manual,omitempty"`
	IdempotencyKey          string    `json:"idempotencyKey,omitempty"`
	DNSKEYTTL               int64     `json:"dnskeyTtlSeconds,omitempty"`
	ZoneTTL                 int64     `json:"zoneTtlSeconds,omitempty"`
	ParentDSTTL             int64     `json:"parentDsTtlSeconds,omitempty"`
	EvidenceAt              time.Time `json:"evidenceAt,omitempty"`
	RegistrarCTID           string    `json:"registrarCtid,omitempty"`
	RegistrarSTID           string    `json:"registrarStid,omitempty"`
	RegistrarJobID          int64     `json:"registrarJobId,omitempty"`
	RegistrarJobStatus      string    `json:"registrarJobStatus,omitempty"`
	RegistrarAttemptedAt    time.Time `json:"registrarAttemptedAt,omitempty"`
	RegistrarPayloadHash    string    `json:"registrarPayloadHash,omitempty"`
	ParentMode              string    `json:"parentMode,omitempty"`
	DiscoveredAt            time.Time `json:"discoveredAt,omitempty"`
	KeysetFingerprint       string    `json:"keysetFingerprint,omitempty"`
	EnrollmentDisposition   string    `json:"enrollmentDisposition,omitempty"`
}

// Active reports whether the workflow has a transition in progress.
func (w Workflow) Active() bool { return w.Phase != "" && w.Phase != PhaseIdle }

// State is the complete atomically persisted controller state.
type State struct {
	Version           int                     `json:"version"`
	EnrollmentArmedAt time.Time               `json:"enrollmentArmedAt,omitempty"`
	Workflows         map[string]Workflow     `json:"workflows"`
	Idempotency       map[string]string       `json:"idempotency"`
	Notifications     map[string]Notification `json:"notifications"`
}

// Notification is a durable completion or blocked event awaiting delivery.
type Notification struct {
	ID            string    `json:"id"`
	Event         string    `json:"event,omitempty"`
	Zone          string    `json:"zone"`
	Kind          Kind      `json:"kind"`
	CompletedAt   time.Time `json:"completedAt"`
	OldKeyID      int       `json:"oldKeyId,omitempty"`
	NewKeyID      int       `json:"newKeyId,omitempty"`
	NewZSKID      int       `json:"newZskId,omitempty"`
	RegistrarSTID string    `json:"registrarStid,omitempty"`
	Attempts      int       `json:"attempts,omitempty"`
	NextAttemptAt time.Time `json:"nextAttemptAt,omitempty"`
	LastError     string    `json:"lastError,omitempty"`
	DeliveredAt   time.Time `json:"deliveredAt,omitempty"`
}

// WorkflowKey returns the stable map key for one zone workflow.
func WorkflowKey(zone string, kind Kind) string { return zone + "|" + string(kind) }
