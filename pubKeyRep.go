package dkim

import (
	"crypto/rsa"
	"fmt"
	"net"
)

// pubKeyRep represents a parsed version of public key record
type pubKeyRep struct {
	Version      string
	HashAlgo     []string
	KeyType      string
	Note         string
	PubKey       rsa.PublicKey
	ServiceType  []string
	FlagTesting  bool // flag y
	FlagIMustBeD bool // flag i
}

func newPubKeyFromDnsTxt(selector, domain string) (*pubKeyRep, error) {
	txt, err := net.LookupTXT(selector + "._domainkey." + domain)
	fmt.Println(txt, err)

	return nil, nil
}
