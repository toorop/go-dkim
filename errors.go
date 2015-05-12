package dkim

import (
	"errors"
)

var (
	// ErrConfigPrivateKeyRequired when there not private key in config
	ErrSignPrivateKeyRequired = errors.New("PrivateKey is required")

	// ErrSignDomainRequired when there is no domain defined in config
	ErrSignDomainRequired = errors.New("Domain is required")

	// ErrSignSelectorRequired when there is no Selcteir defined in config
	ErrSignSelectorRequired = errors.New("Selector is required")

	// If Headers is specified it should at least contain 'from'
	ErrSignHeaderShouldContainsFrom = errors.New("header must contains 'from' field")

	// If bad Canonicalization parameter
	ErrSignBadCanonicalization = errors.New("bad Canonicalization parameter")

	// when unable to parse private key
	ErrCandNotParsePrivateKey = errors.New("can not parse private key, check format (pem) and validity")

	// Bad algorithm
	ErrSignBadAlgo = errors.New("bad algorithm. Only rsa-sha1 or rsa-sha256 are permitted")

	// ErrBadMailFormat
	ErrBadMailFormat = errors.New("bad mail format")

	// ErrBadMailFormatHeaders
	ErrBadMailFormatHeaders = errors.New("bad mail format found in headers")

	// ErrBadDKimTagLBodyTooShort
	ErrBadDKimTagLBodyTooShort = errors.New("bad tag l or bodyLength option. Body length < l value")

	// ErrDkimHeaderNotFound when there's no DKIM-Signature header in an email we have to verify
	ErrDkimHeaderNotFound = errors.New("no DKIM-Signature header field found ")

	// ErrDkimHeaderBTagNotFound when there's no b tag
	ErrDkimHeaderBTagNotFound = errors.New("no tag 'b' found in dkim header")

	// ErrDkimHeaderNoFromInHTag
	ErrDkimHeaderNoFromInHTag = errors.New("'from' header is missing in h tag")

	// ErrDkimHeaderMissingRequiredTag when a required tag is missing
	ErrDkimHeaderMissingRequiredTag = errors.New("signature missing required tag")

	// ErrDkimHeaderDomainMismatch if i tag is not a sub domain of d tag
	ErrDkimHeaderDomainMismatch = errors.New("domain mismatch")

	// Version not supported
	ErrDkimVersionNotsupported = errors.New("incompatible version")

	// Query method unsopported
	errQueryMethodNotsupported = errors.New("query method not supported")

	// ErrVerifyBodyHash when body hash doesn't verify
	ErrVerifyBodyHash = errors.New("body hash did not verify")
)
