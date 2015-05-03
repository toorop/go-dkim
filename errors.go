package dkim

import (
	"errors"
)

var (
	// ErrConfigPrivateKeyRequired when there not private key in config
	ErrSignPrivateKeyRequired = errors.New("PrivateKey is required in config")

	// ErrSignDomainRequired when there is no domain defined in config
	ErrSignDomainRequired = errors.New("Domain is required in config")

	// ErrSignSelectorRequired when there is no Selcteir defined in config
	ErrSignSelectorRequired = errors.New("Selector is required in config")

	// If Headers is specified it should at least contain 'from'
	ErrSignHeaderShouldContainsFrom = errors.New("Header must contains 'from' field")

	// If bad Canonicalization parameter
	ErrSignBadCanonicalization = errors.New("bad Canonicalization parameter")

	// Bad algorithm
	ErrSignBadAlgo = errors.New("bar algorithm. Only rsa-sha1 or rsa-sha256 are permitted")
)
