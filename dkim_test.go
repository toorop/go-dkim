package dkim

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	privKey = `MIICXQIBAAKBgQDNUXO+Qsl1tw+GjrqFajz0ERSEUs1FHSL/+udZRWn1Atw8gz0+
tcGqhWChBDeU9gY5sKLEAZnX3FjC/T/IbqeiSM68kS5vLkzRI84eiJrm3+IieUqI
IicsO+WYxQs+JgVx5XhpPjX4SQjHtwEC2xKkWnEv+VPgO1JWdooURcSC6QIDAQAB
AoGAM9exRgVPIS4L+Ynohu+AXJBDgfX2ZtEomUIdUGk6i+cg/RaWTFNQh2IOOBn8
ftxwTfjP4HYXBm5Y60NO66klIlzm6ci303IePmjaj8tXQiriaVA0j4hmW+xgnqQX
PubFzfnR2eWLSOGChrNFbd3YABC+qttqT6vT0KpFyLdn49ECQQD3zYCpgelb0EBo
gc5BVGkbArcknhPwO39coPqKM4csu6cgI489XpF7iMh77nBTIiy6dsDdRYXZM3bq
ELTv6K4/AkEA1BwsIZG51W5DRWaKeobykQIB6FqHLW+Zhedw7BnxS8OflYAcSWi4
uGhq0DPojmhsmUC8jUeLe79CllZNP3LU1wJBAIZcoCnI7g5Bcdr4nyxfJ4pkw4cQ
S4FT0XAZPR/YZrADo8/SWCWPdFTGSuaf17nL6vLD1zljK/skY5LwshrvUCMCQQDM
MY7ehj6DVFHYlt2LFSyhInCZscTencgK24KfGF5t1JZlwt34YaMqjAMACmi/55Fc
e7DIxW5nI/nDZrOY+EAjAkA3BHUx3PeXkXJnXjlh7nGZmk/v8tB5fiofAwfXNfL7
bz0ZrT2Caz995Dpjommh5aMpCJvUGsrYCG6/Pbha9NXl`

	pubKey = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNUXO+Qsl1tw+GjrqFajz0ERSE
Us1FHSL/+udZRWn1Atw8gz0+tcGqhWChBDeU9gY5sKLEAZnX3FjC/T/IbqeiSM68
kS5vLkzRI84eiJrm3+IieUqIIicsO+WYxQs+JgVx5XhpPjX4SQjHtwEC2xKkWnEv
+VPgO1JWdooURcSC6QIDAQAB`

	domain = "tmail.io"

	selector = "test"
)

var email = `Received: (qmail 28277 invoked from network); 1 May 2015 09:43:37 -0000
Received: (qmail 21323 invoked from network); 1 May 2015 09:48:39 -0000
MIME-Version: 1.0
Date: Fri, 1 May 2015 11:48:37 +0200
Message-ID: <CADu37kTXBeNkJdXc4bSF8DbJnXmNjkLbnswK6GzG_2yn7U7P6w@tmail.io>
Subject: Test DKIM
From: =?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@tmail.io>
To: =?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@toorop.fr>
Content-Type: text/plain; charset=UTF-8` + "\r\n\r\n" + `Hello world
-- 
Toorop` + "\r\n\r\n\r\n\r\n\r\n\r\n\r\n"

func Test_NewSigOptions(t *testing.T) {
	options := NewSigOptions()
	assert.Equal(t, "rsa-sha256", options.Algo)
	assert.Equal(t, "simple/simple", options.Canonicalization)
}

func Test_SignConfig(t *testing.T) {
	emailReader := bytes.NewReader([]byte(email))
	options := NewSigOptions()
	_, err := Sign(emailReader, options)
	assert.NotNil(t, err)
	// && err No private key
	assert.EqualError(t, err, ErrSignPrivateKeyRequired.Error())
	options.PrivateKey = "toto"
	_, err = Sign(emailReader, options)

	// Domain
	assert.EqualError(t, err, ErrSignDomainRequired.Error())
	options.Domain = "toorop.fr"
	_, err = Sign(emailReader, options)

	// Selector
	assert.Error(t, err, ErrSignSelectorRequired.Error())
	options.Selector = "default"
	_, err = Sign(emailReader, options)
	assert.NoError(t, err)

	// Canonicalization
	options.Canonicalization = "simple/relaxed/simple"
	_, err = Sign(emailReader, options)
	assert.EqualError(t, err, ErrSignBadCanonicalization.Error())

	options.Canonicalization = "simple/relax"
	_, err = Sign(emailReader, options)
	assert.EqualError(t, err, ErrSignBadCanonicalization.Error())

	options.Canonicalization = "relaxed"
	_, err = Sign(emailReader, options)
	assert.NoError(t, err)

	options.Canonicalization = "SiMple/relAxed"
	_, err = Sign(emailReader, options)
	assert.NoError(t, err)

	// header
	options.Headers = []string{"toto"}
	_, err = Sign(emailReader, options)
	assert.EqualError(t, err, ErrSignHeaderShouldContainsFrom.Error())

	options.Headers = []string{"To", "From"}
	_, err = Sign(emailReader, options)
	assert.NoError(t, err)
}

func Test_Sign(t *testing.T) {
	emailReader := bytes.NewReader([]byte(email))
	options := NewSigOptions()
	options.PrivateKey = privKey
	options.Canonicalization = "simple/relaxed"
	options.Domain = domain
	options.Selector = selector
	emailReader, err := Sign(emailReader, options)
	assert.NoError(t, err)
}
