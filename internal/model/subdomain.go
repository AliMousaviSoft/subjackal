package model

type DNSRecordType string

const (
	RecordA        DNSRecordType = "A"
	RecordAAAA     DNSRecordType = "AAAA"
	RecordCNAME    DNSRecordType = "CNAME"
	RecordNS       DNSRecordType = "NS"
	RecordNXDOMAIN DNSRecordType = "NXDOMAIN"
)

type Status string

const (
	StatusAlive      Status = "alive"
	StatusNXDOMAIN   Status = "nxdomain"
	StatusSuspicious Status = "suspicious"
	StatusVulnerable Status = "vulnerable"
	StatusDismissed  Status = "dismissed" // was candidate, chain resolved to IP
)

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// ConfidenceScore holds weighted signal scores
// Max possible: 190
// Vulnerable threshold: >= 120
// Suspicious threshold: >= 50
type ConfidenceScore struct {
	CNAMEMatch    int // +70  CNAME points to known third-party service
	NXDOMAINBack  int // +20  CNAME target is NXDOMAIN
	HTTPMatch     int // +100 HTTP body fingerprint confirmed
	NSUnregistered int // +150 NS delegation to unregistered domain (full zone takeover)
}

func (s *ConfidenceScore) Total() int {
	return s.CNAMEMatch + s.NXDOMAINBack + s.HTTPMatch + s.NSUnregistered
}

func (s *ConfidenceScore) Level() Confidence {
	t := s.Total()
	switch {
	case t >= 120:
		return ConfidenceHigh
	case t >= 50:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

type Subdomain struct {
	Domain           string
	Root             string
	RecordType       DNSRecordType
	IPs              []string
	CNAMEChain       []string
	NSRecords        []string
	IsWildcard       bool
	CNAMETarget      string
	ServiceProvider  string
	TakeoverPossible bool
	Confidence       Confidence
	Score            ConfidenceScore
	Fingerprint      string
	Status           Status
	Note             string
}