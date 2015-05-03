package dkim

import (
	"bytes"
	"io/ioutil"
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
	if len(p) == 1 {
		options.Canonicalization = options.Canonicalization + "/simple"
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
		h = strings.ToLower(h)
		options.Headers[i] = h
		if h == "from" {
			hasFrom = true
		}
	}
	if !hasFrom {
		return nil, ErrSignHeaderShouldContainsFrom
	}

	// Normalize
	//normalizedHeaders, NormalizedBody, err := normalize(email, options)

	canonicalize(email, options)

	return nil, nil
}

func canonicalize(emailReader *bytes.Reader, options sigOptions) (headers, body []byte, err error) {
	var email []byte
	email, err = ioutil.ReadAll(emailReader)
	emailReader.Seek(0, 0)
	if err != nil {
		return
	}

	parts := bytes.SplitN(email, []byte{13, 10, 13, 10}, 2)

	canonicalizations := strings.Split(options.Canonicalization, "/")
	// canonicalyze body
	if canonicalizations[1] == "simple" {
		body = bytes.TrimRight(parts[1], "\r\n")
		body = append(body, []byte{13, 10}...)
	} else {
		for _, line := range bytes.Split(parts[1], []byte{10}) {
			println(line)
		}
	}

	println(string(parts[0]))
	println("\r\n")
	println(string(parts[1]))
	println(string(body))

	return
}
