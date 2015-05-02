package dkim

import (
	"bytes"
	"time"
)

// sigOptions represents signing options
type sigOptions struct {
	PrivateKey       string
	Domain           string
	Selector         string
	Auid             string
	Canonicalization string
	Algo             string
	Headers          []string
	Timestamp        time.Time
	Expiration       time.Time
}

// NewSigOption returns new sigoption with some defaults value
func NewSigOptions() sigOptions {
	return sigOptions{
		Canonicalization: "simple/simple",
		Algo:             "rsa-sha256",
	}
}

// Sign signs an email
func Sign(email *bytes.Reader, options sigOptions) (*bytes.Reader, error) {
	// check config

	// private key (not empty & TODO: valid)
	if options.PrivateKey == "" {
		return nil, ErrConfigNoPrivateKey
	}

	return nil, nil
}
