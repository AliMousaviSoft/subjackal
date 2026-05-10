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
)

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

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
	Fingerprint      string
	Status           Status
	Note             string
}
