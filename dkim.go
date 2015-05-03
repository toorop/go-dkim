package dkim

import (
	"bytes"
	"strings"
	"time"
)

// sigOptions represents signing options
type sigOptions struct {

	// DKIM version (default 1)
	Version uint

	// Private key used for signing (required)
	PrivateKey string

	// Domain (required)
	Domain string

	// Selector (required)
	Selector string

	// The Agent of User IDentifier
	Auid string

	// Message canonicalization (plain-text; OPTIONAL, default is
	// "simple/simple").  This tag informs the Verifier of the type of
	// canonicalization used to prepare the message for signing.
	Canonicalization string

	// The algorithm used to generate the signature
	//"rsa-sha1" or "rsa-sha256"
	Algo string

	// Signed header fields
	Headers []string

	// Body length count( if set to 0 this tag is ommited in Dkim header)
	BodyLength uint

	// Query Methods used to retrieve the public key
	QueryMethods []string

	// Add a signature timestamp
	AddSignatureTimestamp bool

	// Time validity of the signature (0=never)
	SignatureExpireIn time.Duration
}

// NewSigOption returns new sigoption with some defaults value
func NewSigOptions() sigOptions {
	return sigOptions{
		Version:               1,
		Canonicalization:      "simple/simple",
		Algo:                  "rsa-sha256",
		Headers:               []string{"from"},
		BodyLength:            0,
		QueryMethods:          []string{"dns/txt"},
		AddSignatureTimestamp: false,
		SignatureExpireIn:     0 * time.Second,
	}
}

// Sign signs an email
func Sign(email *bytes.Reader, options sigOptions) (*bytes.Reader, error) {
	// check && sanitize config

	// PrivateKey (required & TODO: valid)
	if options.PrivateKey == "" {
		return nil, ErrSignPrivateKeyRequired
	}

	// Domain required
	if options.Domain == "" {
		return nil, ErrSignDomainRequired
	}

	// Selector required
	if options.Selector == "" {
		return nil, ErrSignSelectorRequired
	}

	// Canonicalization
	options.Canonicalization = strings.ToLower(options.Canonicalization)
	p := strings.Split(options.Canonicalization, "/")
	if len(p) > 2 {
		return nil, ErrSignBadCanonicalization
	}
	for _, c := range p {
		if c != "simple" && c != "relaxed" {
			return nil, ErrSignBadCanonicalization
		}
	}

	// Algo
	options.Algo = strings.ToLower(options.Algo)
	if options.Algo != "rsa-sha1" && options.Algo != "rsa-sha256" {
		return nil, ErrSignBadAlgo
	}

	// Header must contain "from"
	// normalize -> strtlower
	hasFrom := false
	for i, h := range options.Headers {
		options.Headers[i] = strings.ToLower(h)
		if h == "from" {
			hasFrom = true
		}
	}
	if !hasFrom {
		return nil, ErrSignHeaderShouldContainsFrom
	}

	//

	return nil, nil
}
