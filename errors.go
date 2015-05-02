package dkim

import (
	"errors"
)

var (
	// ErrConfigNoPrivateKey when there not private key in config
	ErrConfigNoPrivateKey = errors.New("private key not defined in config")
	// ErrConfigNoDomain when there is no domain defined in config
	ErrConfigNoDomain = errors.New("domain not defined in config")
)
