package dkim

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

const (
	privKey = `-----BEGIN RSA PRIVATE KEY-----
	MIICXQIBAAKBgQDNUXO+Qsl1tw+GjrqFajz0ERSEUs1FHSL/+udZRWn1Atw8gz0+
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
bz0ZrT2Caz995Dpjommh5aMpCJvUGsrYCG6/Pbha9NXl
-----END RSA PRIVATE KEY-----`

	pubKey = `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNUXO+Qsl1tw+GjrqFajz0ERSE
Us1FHSL/+udZRWn1Atw8gz0+tcGqhWChBDeU9gY5sKLEAZnX3FjC/T/IbqeiSM68
kS5vLkzRI84eiJrm3+IieUqIIicsO+WYxQs+JgVx5XhpPjX4SQjHtwEC2xKkWnEv
+VPgO1JWdooURcSC6QIDAQAB`

	domain = "tmail.io"

	selector = "test"
)

var email = "Received: (qmail 28277 invoked from network); 1 May 2015 09:43:37 -0000" + CRLF +
	"Received: (qmail 21323 invoked from network); 1 May 2015 09:48:39 -0000" + CRLF +
	"Received: from mail483.ha.ovh.net (b6.ovh.net [213.186.33.56])" + CRLF +
	" by mo51.mail-out.ovh.net (Postfix) with SMTP id A6E22FF8934" + CRLF +
	" for <toorop@toorop.fr>; Mon,  4 May 2015 14:00:47 +0200 (CEST)" + CRLF +
	"MIME-Version: 1.0" + CRLF +
	"Date: Fri, 1 May 2015 11:48:37 +0200" + CRLF +
	"Message-ID: <CADu37kTXBeNkJdXc4bSF8DbJnXmNjkLbnswK6GzG_2yn7U7P6w@tmail.io>" + CRLF +
	"Subject: Test DKIM" + CRLF +
	"From: =?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@tmail.io>" + CRLF +
	"To: =?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@toorop.fr>" + CRLF +
	"Content-Type: text/plain; charset=UTF-8" + CRLF + CRLF +
	"Hello world" + CRLF //+
//"line with trailing space         " + CRLF +
//"line with           space         " + CRLF +
//"-- " + CRLF +
//"Toorop" // + CRLF + CRLF + CRLF + CRLF + CRLF + CRLF

var headerSimple = "From: =?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@tmail.io>" + CRLF +
	"Date: Fri, 1 May 2015 11:48:37 +0200" + CRLF +
	"MIME-Version: 1.0" + CRLF +
	"Received: from mail483.ha.ovh.net (b6.ovh.net [213.186.33.56])" + CRLF +
	" by mo51.mail-out.ovh.net (Postfix) with SMTP id A6E22FF8934" + CRLF +
	" for <toorop@toorop.fr>; Mon,  4 May 2015 14:00:47 +0200 (CEST)" + CRLF +
	"Received: (qmail 21323 invoked from network); 1 May 2015 09:48:39 -0000" + CRLF +
	"In-Reply-To:" + CRLF

var headerRelaxed = "from:=?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@tmail.io>" + CRLF +
	"date:Fri, 1 May 2015 11:48:37 +0200" + CRLF +
	"mime-version:1.0" + CRLF +
	"received:from mail483.ha.ovh.net (b6.ovh.net [213.186.33.56]) by mo51.mail-out.ovh.net (Postfix) with SMTP id A6E22FF8934 for <toorop@toorop.fr>; Mon, 4 May 2015 14:00:47 +0200 (CEST)" + CRLF +
	"received:(qmail 21323 invoked from network); 1 May 2015 09:48:39 -0000" + CRLF +
	"in-reply-to:" + CRLF

var bodySimple = "Hello world" + CRLF +
	"line with trailing space         " + CRLF +
	"line with           space         " + CRLF +
	"-- " + CRLF +
	"Toorop  " + CRLF

var bodyRelaxed = "Hello world" + CRLF +
	"line with trailing space" + CRLF +
	"line with space" + CRLF +
	"--" + CRLF +
	"Toorop" + CRLF

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
	options.PrivateKey = privKey
	_, err = Sign(emailReader, options)
	emailReader.Seek(0, 0)

	// Domain
	assert.EqualError(t, err, ErrSignDomainRequired.Error())
	options.Domain = "toorop.fr"
	_, err = Sign(emailReader, options)
	emailReader.Seek(0, 0)

	// Selector
	assert.Error(t, err, ErrSignSelectorRequired.Error())
	options.Selector = "default"
	_, err = Sign(emailReader, options)
	assert.NoError(t, err)
	emailReader.Seek(0, 0)

	// Canonicalization
	options.Canonicalization = "simple/relaxed/simple"
	_, err = Sign(emailReader, options)
	assert.EqualError(t, err, ErrSignBadCanonicalization.Error())
	emailReader.Seek(0, 0)

	options.Canonicalization = "simple/relax"
	_, err = Sign(emailReader, options)
	emailReader.Seek(0, 0)
	assert.EqualError(t, err, ErrSignBadCanonicalization.Error())
	emailReader.Seek(0, 0)

	options.Canonicalization = "relaxed"
	_, err = Sign(emailReader, options)
	assert.NoError(t, err)
	emailReader.Seek(0, 0)

	options.Canonicalization = "SiMple/relAxed"
	_, err = Sign(emailReader, options)
	assert.NoError(t, err)
	emailReader.Seek(0, 0)

	// header
	options.Headers = []string{"toto"}
	_, err = Sign(emailReader, options)
	assert.EqualError(t, err, ErrSignHeaderShouldContainsFrom.Error())
	emailReader.Seek(0, 0)

	options.Headers = []string{"To", "From"}
	_, err = Sign(emailReader, options)
	assert.NoError(t, err)
	emailReader.Seek(0, 0)
}

func Test_canonicalize(t *testing.T) {
	emailReader := bytes.NewReader([]byte(email))
	options := NewSigOptions()
	options.Headers = []string{"from", "date", "mime-version", "received", "received", "In-Reply-To"}
	// simple/simple
	options.Canonicalization = "simple/simple"
	header, body, err := canonicalize(emailReader, options)
	assert.NoError(t, err)
	assert.Equal(t, []byte(headerSimple), header)
	assert.Equal(t, []byte(bodySimple), body)

	// relaxed/relaxed
	options.Canonicalization = "relaxed/relaxed"
	header, body, err = canonicalize(emailReader, options)
	assert.NoError(t, err)
	assert.Equal(t, []byte(headerRelaxed), header)
	assert.Equal(t, []byte(bodyRelaxed), body)

}

func Test_Sign(t *testing.T) {
	emailReader := bytes.NewReader([]byte(email))
	options := NewSigOptions()
	options.PrivateKey = privKey
	options.Canonicalization = "relaxed/relaxed"
	options.Domain = domain
	options.Selector = selector
	options.AddSignatureTimestamp = true
	options.SignatureExpireIn = 3600
	options.Headers = []string{"from"}
	emailReader, err := Sign(emailReader, options)
	assert.NoError(t, err)
	raw, _ := ioutil.ReadAll(emailReader)
	fmt.Println(string(raw))
}
