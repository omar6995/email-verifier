package emailverifier

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/smtp"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// SMTP stores all information for SMTP verification lookup
type SMTP struct {
	HostExists  bool `json:"host_exists"` // is the host exists?
	FullInbox   bool `json:"full_inbox"`  // is the email account's inbox full?
	CatchAll    bool `json:"catch_all"`   // does the domain have a catch-all email address?
	Deliverable bool `json:"deliverable"` // can send an email to the email server?
	Disabled    bool `json:"disabled"`    // is the email blocked or disabled by the provider?
}

// CheckSMTP performs an email verification on the passed domain via SMTP
//   - the domain is the passed email domain
//   - username is used to check the deliverability of specific email address,
//
// if server is catch-all server, username will not be checked
func (v *Verifier) CheckSMTP(domain, username string) (*SMTP, error) {
	log.Printf("[DEBUG-VERIFIER] CheckSMTP started for domain=%s, username=%s", domain, username)
	ret := SMTP{
		CatchAll: true, // Default catchAll to true
	}

	if !v.smtpCheckEnabled {
		log.Printf("[DEBUG-VERIFIER] SMTP check disabled.")
		return &ret, nil
	}

	var err error
	email := fmt.Sprintf("%s@%s", username, domain)

	// Dial any SMTP server that will accept a connection
	client, mx, err := newSMTPClient(domain, v.proxyURI, v.connectTimeout, v.operationTimeout, v.debugModeEnabled)
	if err != nil {
		log.Printf("[DEBUG-VERIFIER] newSMTPClient error: %v", err)
		return &ret, ParseSMTPError(err)
	}
	log.Printf("[DEBUG-VERIFIER] Connected to MX: %s", mx.Host)

	// Defer quit the SMTP connection
	defer client.Close()

	// Check by api when enabled and host recognized.
	for _, apiVerifier := range v.apiVerifiers {
		if apiVerifier.isSupported(strings.ToLower(mx.Host)) {
			return apiVerifier.check(domain, username)
		}
	}

	// Sets the HELO/EHLO hostname
	log.Printf("[DEBUG-VERIFIER] Sending EHLO/HELO %s", v.helloName)
	if err = client.Hello(v.helloName); err != nil {
		log.Printf("[DEBUG-VERIFIER] EHLO/HELO error: %v", err)
		return &ret, ParseSMTPError(err)
	}
	log.Printf("[DEBUG-VERIFIER] EHLO/HELO successful")

	// Sets the from email
	log.Printf("[DEBUG-VERIFIER] Sending MAIL FROM: %s", v.fromEmail)
	if err = client.Mail(v.fromEmail); err != nil {
		log.Printf("[DEBUG-VERIFIER] MAIL FROM error: %v", err)
		return &ret, ParseSMTPError(err)
	}
	log.Printf("[DEBUG-VERIFIER] MAIL FROM successful")

	// Host exists if we've successfully formed a connection
	ret.HostExists = true

	// Default sets catch-all to true
	ret.CatchAll = true

	if v.catchAllCheckEnabled {
		// Checks the deliver ability of a randomly generated address in
		// order to verify the existence of a catch-all and etc.
		randomEmail := GenerateRandomEmail(domain)
		log.Printf("[DEBUG-VERIFIER] Sending RCPT TO (catch-all check): %s", randomEmail)
		if err = client.Rcpt(randomEmail); err != nil {
			log.Printf("[DEBUG-VERIFIER] RCPT TO (catch-all check) error: %v", err)
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
			log.Printf("[DEBUG-VERIFIER] RCPT TO (catch-all check) successful")
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
		log.Printf("[DEBUG-VERIFIER] No username provided, skipping final RCPT TO")
		return &ret, nil
	}

	log.Printf("[DEBUG-VERIFIER] Sending RCPT TO: %s", email)
	if err = client.Rcpt(email); err == nil {
		log.Printf("[DEBUG-VERIFIER] RCPT TO successful")
		ret.Deliverable = true
	} else {
		log.Printf("[DEBUG-VERIFIER] RCPT TO error: %v", err)
	}

	log.Printf("[DEBUG-VERIFIER] CheckSMTP finished for %s", email)
	return &ret, nil
}

// newSMTPClient generates a new available SMTP client
func newSMTPClient(domain, proxyURI string, connectTimeout, operationTimeout time.Duration, debugModeEnabled bool) (*smtp.Client, *net.MX, error) {
	if debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] newSMTPClient looking for MX records for domain=%s", domain)
	}
	domain = domainToASCII(domain)
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		if debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] MX lookup error: %v", err)
		}
		return nil, nil, err
	}

	if len(mxRecords) == 0 {
		if debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] No MX records found for %s", domain)
		}
		return nil, nil, errors.New("No MX records found")
	}
	if debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] Found %d MX records for %s", len(mxRecords), domain)
	}
	// Create a channel for receiving response from
	ch := make(chan interface{}, 1)
	selectedMXCh := make(chan *net.MX, 1)

	// Done indicates if we're still waiting on dial responses
	var done bool

	// mutex for data race
	var mutex sync.Mutex

	// Attempt to connect to all SMTP servers concurrently
	for i, r := range mxRecords {
		addr := r.Host + smtpPort
		index := i
		if debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] Attempting to dial MX record %d: %s", i, addr)
		}
		go func() {
			c, err := dialSMTP(addr, proxyURI, connectTimeout, operationTimeout, debugModeEnabled)
			if err != nil {
				if debugModeEnabled {
					log.Printf("[DEBUG-VERIFIER] Dial error for %s: %v", addr, err)
				}
				if !done {
					ch <- err
				}
				return
			}
			if debugModeEnabled {
				log.Printf("[DEBUG-VERIFIER] Dial successful for %s", addr)
			}

			// Place the client on the channel or close it
			mutex.Lock()
			switch {
			case !done:
				done = true
				ch <- c
				if debugModeEnabled {
					log.Printf("[DEBUG-VERIFIER] Selected MX: %s", mxRecords[index].Host)
				}
				selectedMXCh <- mxRecords[index]
			default:
				if debugModeEnabled {
					log.Printf("[DEBUG-VERIFIER] Closing redundant connection to %s", addr)
				}
				c.Close()
			}
			mutex.Unlock()
		}()
	}

	// Collect errors or return a client
	var errs []error
	for {
		res := <-ch
		switch r := res.(type) {
		case *smtp.Client:
			selectedMX := <-selectedMXCh
			if debugModeEnabled {
				log.Printf("[DEBUG-VERIFIER] newSMTPClient returning client connected to %s", selectedMX.Host)
			}
			return r, selectedMX, nil
		case error:
			errs = append(errs, r)
			if len(errs) == len(mxRecords) {
				if debugModeEnabled {
					log.Printf("[DEBUG-VERIFIER] newSMTPClient failed, returning first error: %v", errs[0])
				}
				return nil, nil, errs[0]
			}
		default:
			if debugModeEnabled {
				log.Printf("[DEBUG-VERIFIER] newSMTPClient unexpected response type")
			}
			return nil, nil, errors.New("Unexpected response dialing SMTP server")
		}
	}

}

// dialSMTP is a timeout wrapper for smtp.Dial. It attempts to dial an
// SMTP server (socks5 proxy supported) and fails with a timeout if timeout is reached while
// attempting to establish a new connection
func dialSMTP(addr, proxyURI string, connectTimeout, operationTimeout time.Duration, debugModeEnabled bool) (*smtp.Client, error) {
	if debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] dialSMTP called for addr=%s, proxy=%s", addr, proxyURI)
	}
	// Dial the new smtp connection
	var conn net.Conn
	var err error

	if proxyURI != "" {
		if debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] Attempting proxy connection to %s via %s", addr, proxyURI)
		}
		conn, err = establishProxyConnection(addr, proxyURI, connectTimeout, debugModeEnabled)
	} else {
		if debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] Attempting direct connection to %s", addr)
		}
		conn, err = establishConnection(addr, connectTimeout, debugModeEnabled)
	}
	if err != nil {
		if debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] Connection failed for %s: %v", addr, err)
		}
		return nil, err
	}
	if debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] Connection successful for %s", addr)
	}

	// Set specific timeouts for writing and reading
	if debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] Setting deadline for %s", addr)
	}
	err = conn.SetDeadline(time.Now().Add(operationTimeout))
	if err != nil {
		if debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] SetDeadline error for %s: %v", addr, err)
		}
		return nil, err
	}

	host, _, _ := net.SplitHostPort(addr)
	if debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] Creating smtp.Client for %s", host)
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		if debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] smtp.NewClient error for %s: %v", host, err)
		}
		return nil, err
	}
	if debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] smtp.Client created successfully for %s", host)
	}
	return client, nil
}

// GenerateRandomEmail generates a random email address using the domain passed. Used
// primarily for checking the existence of a catch-all address
func GenerateRandomEmail(domain string) string {
	r := make([]byte, 32)
	for i := 0; i < 32; i++ {
		r[i] = alphanumeric[rand.Intn(len(alphanumeric))]
	}
	return fmt.Sprintf("%s@%s", string(r), domain)

}

// establishConnection connects to the address on the named network address.
func establishConnection(addr string, timeout time.Duration, debugModeEnabled bool) (net.Conn, error) {
	if debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] establishConnection dialing %s with timeout %s", addr, timeout)
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		if debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] establishConnection error: %v", err)
		}
		return nil, err
	}
	if debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] establishConnection successful for %s", addr)
	}
	return conn, nil
}

// establishProxyConnection connects to the address on the named network address
// via proxy protocol
func establishProxyConnection(addr, proxyURI string, timeout time.Duration, debugModeEnabled bool) (net.Conn, error) {
	if debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] establishProxyConnection dialing %s via %s with timeout %s", addr, proxyURI, timeout)
	}
	u, err := url.Parse(proxyURI)
	if err != nil {
		if debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] Proxy URI parse error: %v", err)
		}
		return nil, err
	}
	if debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] Creating proxy dialer for scheme: %s", u.Scheme)
	}
	dialer, err := proxy.FromURL(u, nil)
	if err != nil {
		if debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] Proxy FromURL error: %v", err)
		}
		return nil, err
	}

	// https://github.com/golang/go/issues/37549#issuecomment-1178745487
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] Dialing %s via proxy context dialer", addr)
	}
	conn, err := dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", addr)
	if err != nil {
		if debugModeEnabled {
			log.Printf("[DEBUG-VERIFIER] Proxy DialContext error: %v", err)
		}
		return nil, err
	}
	if debugModeEnabled {
		log.Printf("[DEBUG-VERIFIER] Proxy DialContext successful for %s", addr)
	}
	return conn, nil
}
