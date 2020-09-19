package dnscrypt

const (
	// Complete : Transaction completed successfully
	Complete = iota
	// SendFailed : Failed to send query
	SendFailed
	// Error : Got no response
	Error
	// BadQuery : Malformed input
	BadQuery
	// BadResponse : Response was invalid
	BadResponse
	// InternalError : This should never happen
	InternalError
)

type dnscryptError struct {
	status int
	err    error
}

func (e *dnscryptError) Error() string {
	return e.err.Error()
}

func (e *dnscryptError) Unwrap() error {
	return e.err
}

// Summary is a summary of a DNS transaction, reported when it is complete.
type Summary struct {
	Latency     float64 // Response (or failure) latency in seconds
	Query       []byte
	Response    []byte
	Server      string
	RelayServer string
	Status      int
}

// Listener receives Summaries.
type Listener interface {
	OnDNSCryptQuery(url string) bool
	OnDNSCryptResponse(*Summary)
}
