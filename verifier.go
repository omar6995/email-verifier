package emailverifier

import (
	"fmt"
	"net/http"
	"time"
)

// Verifier is an email verifier. Create one by calling NewVerifier
type Verifier struct {
	smtpCheckEnabled     bool                       // SMTP check enabled or disabled (disabled by default)
	catchAllCheckEnabled bool                       // SMTP catchAll check enabled or disabled (enabled by default)
	domainSuggestEnabled bool                       // whether suggest a most similar correct domain or not (disabled by default)
	gravatarCheckEnabled bool                       // gravatar check enabled or disabled (disabled by default)
	debugModeEnabled     bool                       // Debug logging enabled or disabled (disabled by default)
	fromEmail            string                     // name to use in the `EHLO:` SMTP command, defaults to "user@example.org"
	helloName            string                     // email to use in the `MAIL FROM:` SMTP command. defaults to `localhost`
	schedule             *schedule                  // schedule represents a job schedule
	proxyURI             string                     // use a SOCKS5 proxy to verify the email,
	apiVerifiers         map[string]smtpAPIVerifier // currently support gmail & yahoo, further contributions are welcomed.

	// Timeouts
	connectTimeout   time.Duration // Timeout for establishing connections
	operationTimeout time.Duration // Timeout for SMTP operations (e.g., EHLO, MAIL FROM, etc.)
}

// Result is the result of Email Verification
type Result struct {
	Email        string    `json:"email"`          // passed email address
	Reachable    string    `json:"reachable"`      // an enumeration to describe whether the recipient address is real
	Syntax       Syntax    `json:"syntax"`         // details about the email address syntax
	SMTP         *SMTP     `json:"smtp"`           // details about the SMTP response of the email
	Gravatar     *Gravatar `json:"gravatar"`       // whether or not have gravatar for the email
	Suggestion   string    `json:"suggestion"`     // domain suggestion when domain is misspelled
	Disposable   bool      `json:"disposable"`     // is this a DEA (disposable email address)
	RoleAccount  bool      `json:"role_account"`   // is account a role-based account
	Free         bool      `json:"free"`           // is domain a free email domain
	HasMxRecords bool      `json:"has_mx_records"` // whether or not MX-Records for the domain
}

// additional list of disposable domains set via users of this library
var additionalDisposableDomains map[string]bool = map[string]bool{}

// init loads disposable_domain meta data to disposableSyncDomains which are safe for concurrent use
func init() {
	for d := range disposableDomains {
		disposableSyncDomains.Store(d, struct{}{})
	}
}

// NewVerifier creates a new email verifier
func NewVerifier() *Verifier {
	return &Verifier{
		fromEmail:            defaultFromEmail,
		helloName:            defaultHelloName,
		catchAllCheckEnabled: true,
		apiVerifiers:         map[string]smtpAPIVerifier{},
		connectTimeout:       10 * time.Second,
		operationTimeout:     10 * time.Second,
	}
}

// Verify performs address, misc, mx and smtp checks
func (v *Verifier) Verify(email string) (*Result, error) {

	ret := Result{
		Email:     email,
		Reachable: reachableUnknown,
	}

	syntax := v.ParseAddress(email)
	ret.Syntax = syntax
	if !syntax.Valid {
		return &ret, nil
	}

	ret.Free = v.IsFreeDomain(syntax.Domain)
	ret.RoleAccount = v.IsRoleAccount(syntax.Username)
	ret.Disposable = v.IsDisposable(syntax.Domain)

	// If the domain name is disposable, mx and smtp are not checked.
	if ret.Disposable {
		return &ret, nil
	}

	mx, err := v.CheckMX(syntax.Domain)
	if err != nil {
		return &ret, err
	}
	ret.HasMxRecords = mx.HasMXRecord

	smtp, err := v.CheckSMTP(syntax.Domain, syntax.Username)
	if err != nil {
		return &ret, err
	}
	ret.SMTP = smtp
	ret.Reachable = v.calculateReachable(smtp)

	if v.gravatarCheckEnabled {
		gravatar, err := v.CheckGravatar(email)
		if err != nil {
			return &ret, err
		}
		ret.Gravatar = gravatar
	}

	if v.domainSuggestEnabled {
		ret.Suggestion = v.SuggestDomain(syntax.Domain)
	}

	return &ret, nil
}

// AddDisposableDomains adds additional domains as disposable domains.
func (v *Verifier) AddDisposableDomains(domains []string) *Verifier {
	for _, d := range domains {
		additionalDisposableDomains[d] = true
		disposableSyncDomains.Store(d, struct{}{})
	}
	return v
}

// EnableGravatarCheck enables check gravatar,
// we don't check gravatar by default
func (v *Verifier) EnableGravatarCheck() *Verifier {
	v.gravatarCheckEnabled = true
	return v
}

// DisableGravatarCheck disables check gravatar,
func (v *Verifier) DisableGravatarCheck() *Verifier {
	v.gravatarCheckEnabled = false
	return v
}

// EnableSMTPCheck enables check email by smtp,
// for most ISPs block outgoing SMTP requests through port 25, to prevent spam,
// we don't check smtp by default
func (v *Verifier) EnableSMTPCheck() *Verifier {
	v.smtpCheckEnabled = true
	return v
}

// EnableAPIVerifier API verifier is activated when EnableAPIVerifier for the target vendor.
// ** Please know ** that this is a tricky way (but relatively stable) to check if target vendor's email exists.
// If you use this feature in a production environment, please ensure that you have sufficient backup measures in place, as this may encounter rate limiting or other API issues.
func (v *Verifier) EnableAPIVerifier(name string) error {
	switch name {
	case YAHOO:
		v.apiVerifiers[YAHOO] = newYahooAPIVerifier(http.DefaultClient)
	default:
		return fmt.Errorf("unsupported to enable the API verifier for vendor: %s", name)
	}
	return nil
}

func (v *Verifier) DisableAPIVerifier(name string) {
	delete(v.apiVerifiers, name)
}

// DisableSMTPCheck disables check email by smtp
func (v *Verifier) DisableSMTPCheck() *Verifier {
	v.smtpCheckEnabled = false
	return v
}

// EnableCatchAllCheck enables catchAll check by smtp
// for most ISPs block outgoing catchAll requests through port 25, to prevent spam,
// we don't check catchAll by default
func (v *Verifier) EnableCatchAllCheck() *Verifier {
	v.catchAllCheckEnabled = true
	return v
}

// DisableCatchAllCheck disables catchAll check by smtp
func (v *Verifier) DisableCatchAllCheck() *Verifier {
	v.catchAllCheckEnabled = false
	return v
}

// EnableDomainSuggest will suggest a most similar correct domain when domain misspelled
func (v *Verifier) EnableDomainSuggest() *Verifier {
	v.domainSuggestEnabled = true
	return v
}

// DisableDomainSuggest will not suggest anything
func (v *Verifier) DisableDomainSuggest() *Verifier {
	v.domainSuggestEnabled = false
	return v
}

// EnableAutoUpdateDisposable enables update disposable domains automatically
func (v *Verifier) EnableAutoUpdateDisposable() *Verifier {
	v.stopCurrentSchedule()
	// fetch latest disposable domains before next schedule
	_ = updateDisposableDomains(disposableDataURL)
	// update disposable domains records daily
	v.schedule = newSchedule(24*time.Hour, updateDisposableDomains, disposableDataURL)
	v.schedule.start()
	return v
}

// DisableAutoUpdateDisposable stops previously started schedule job
func (v *Verifier) DisableAutoUpdateDisposable() *Verifier {
	v.stopCurrentSchedule()
	return v

}

// FromEmail sets the emails to use in the `MAIL FROM:` smtp command
func (v *Verifier) FromEmail(email string) *Verifier {
	v.fromEmail = email
	return v
}

// HelloName sets the name to use in the `EHLO:` SMTP command
func (v *Verifier) HelloName(domain string) *Verifier {
	v.helloName = domain
	return v
}

// Proxy sets a SOCKS5 proxy to verify the email,
// proxyURI should be in the format: "socks5://user:password@127.0.0.1:1080?timeout=5s".
// The protocol could be socks5, socks4 and socks4a.
func (v *Verifier) Proxy(proxyURI string) *Verifier {
	v.proxyURI = proxyURI
	return v
}

// ConnectTimeout sets the timeout for establishing connections.
func (v *Verifier) ConnectTimeout(timeout time.Duration) *Verifier {
	v.connectTimeout = timeout
	return v
}

// OperationTimeout sets the timeout for SMTP operations (e.g., EHLO, MAIL FROM, etc.).
func (v *Verifier) OperationTimeout(timeout time.Duration) *Verifier {
	v.operationTimeout = timeout
	return v
}

// EnableDebugMode enables verbose logging for debugging purposes.
func (v *Verifier) EnableDebugMode() *Verifier {
	v.debugModeEnabled = true
	return v
}

// DisableDebugMode disables verbose logging.
func (v *Verifier) DisableDebugMode() *Verifier {
	v.debugModeEnabled = false
	return v
}

func (v *Verifier) calculateReachable(s *SMTP) string {
	if !v.smtpCheckEnabled {
		return reachableUnknown
	}
	if s.Deliverable {
		return reachableYes
	}
	if s.CatchAll {
		return reachableUnknown
	}
	return reachableNo
}

// stopCurrentSchedule stops current running schedule (if exists)
func (v *Verifier) stopCurrentSchedule() {
	if v.schedule != nil {
		v.schedule.stop()
	}
}

// CheckSMTP performs an email verification on the passed domain via SMTP
//   - the domain is the passed email domain
//   - username is used to check the deliverability of specific email address,
//
// if server is catch-all server, username will not be checked
/*
func (v *Verifier) CheckSMTP(domain, username string) (*SMTP, error) {
	if v.debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] CheckSMTP started for domain=%s, username=%s", domain, username)
	}
	ret := SMTP{
		CatchAll: true, // Default catchAll to true
	}

	if !v.smtpCheckEnabled {
		if v.debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] SMTP check disabled.")
		}
		return &ret, nil
	}

	var err error
	email := fmt.Sprintf("%s@%s", username, domain)

	// Dial any SMTP server that will accept a connection
	client, mx, err := newSMTPClient(domain, v.proxyURI, v.connectTimeout, v.operationTimeout, v.debugModeEnabled) // Pass debug flag
	if err != nil {
		if v.debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] newSMTPClient error: %v\n%s", err, debug.Stack())
		}
		return &ret, ParseSMTPError(err)
	}
	if v.debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] Connected to MX: %s", mx.Host)
	}

	// Defer quit the SMTP connection
	defer client.Close()

	// Check by api when enabled and host recognized.
	for _, apiVerifier := range v.apiVerifiers {
		if apiVerifier.isSupported(strings.ToLower(mx.Host)) {
			return apiVerifier.check(domain, username)
		}
	}

	// Sets the HELO/EHLO hostname
	if v.debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] Sending EHLO/HELO %s", v.helloName)
	}
	if err = client.Hello(v.helloName); err != nil {
		if v.debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] EHLO/HELO error: %v\n%s", err, debug.Stack())
		}
		return &ret, ParseSMTPError(err)
	}
	if v.debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] EHLO/HELO successful")
	}

	// Sets the from email
	if v.debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] Sending MAIL FROM: %s", v.fromEmail)
	}
	if err = client.Mail(v.fromEmail); err != nil {
		if v.debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] MAIL FROM error: %v\n%s", err, debug.Stack())
		}
		return &ret, ParseSMTPError(err)
	}
	if v.debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] MAIL FROM successful")
	}

	// Host exists if we've successfully formed a connection
	ret.HostExists = true

	// Default sets catch-all to true
	ret.CatchAll = true

	if v.catchAllCheckEnabled {
		// Checks the deliver ability of a randomly generated address in
		// order to verify the existence of a catch-all and etc.
		randomEmail := GenerateRandomEmail(domain)
		if v.debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] Sending RCPT TO (catch-all check): %s", randomEmail)
		}
		if err = client.Rcpt(randomEmail); err != nil {
			if v.debugModeEnabled {
				log.Printf("[DEBUG-VERIFIER] RCPT TO (catch-all check) error: %v\n%s", err, debug.Stack())
			}
			if e := ParseSMTPError(err); e != nil {
				switch e.Message {
				case ErrFullInbox:
					ret.FullInbox = true
				case ErrNotAllowed:
					ret.Disabled = true
				// If The client typically receives a `550 5.1.1` code as a reply to RCPT TO command,
				// In most cases, this is because the recipient address does not exist.
				case ErrServerUnavailable:
					ret.CatchAll = false
				default:

				}

			}
		} else {
			if v.debugModeEnabled {
				log.Printf("[DEBUG-VERIFIER] RCPT TO (catch-all check) successful")
			}
		}

		// If the email server is a catch-all email server,
		// no need to calibrate deliverable on a specific user
		if ret.CatchAll {
			return &ret, nil
		}
	}

	// If no username provided,
	// no need to calibrate deliverable on a specific user
	if username == "" {
		if v.debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] No username provided, skipping final RCPT TO")
		}
		return &ret, nil
	}

	if v.debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] Sending RCPT TO: %s", email)
	}
	if err = client.Rcpt(email); err == nil {
		if v.debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] RCPT TO successful")
		}
		ret.Deliverable = true
	} else {
		if v.debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] RCPT TO error: %v\n%s", err, debug.Stack())
		}
	}

	if v.debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] CheckSMTP finished for %s", email)
	}
	return &ret, nil
}
*/
