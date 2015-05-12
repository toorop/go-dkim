package dkim

import (
	//"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
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

var emailBase = "Received: (qmail 28277 invoked from network); 1 May 2015 09:43:37 -0000" + CRLF +
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
	"Hello world" + CRLF +
	"line with trailing space         " + CRLF +
	"line with           space         " + CRLF +
	"-- " + CRLF +
	"Toorop" + CRLF + CRLF + CRLF + CRLF + CRLF + CRLF

var emailBaseNoFrom = "Received: (qmail 28277 invoked from network); 1 May 2015 09:43:37 -0000" + CRLF +
	"Received: (qmail 21323 invoked from network); 1 May 2015 09:48:39 -0000" + CRLF +
	"Received: from mail483.ha.ovh.net (b6.ovh.net [213.186.33.56])" + CRLF +
	" by mo51.mail-out.ovh.net (Postfix) with SMTP id A6E22FF8934" + CRLF +
	" for <toorop@toorop.fr>; Mon,  4 May 2015 14:00:47 +0200 (CEST)" + CRLF +
	"MIME-Version: 1.0" + CRLF +
	"Date: Fri, 1 May 2015 11:48:37 +0200" + CRLF +
	"Message-ID: <CADu37kTXBeNkJdXc4bSF8DbJnXmNjkLbnswK6GzG_2yn7U7P6w@tmail.io>" + CRLF +
	"Subject: Test DKIM" + CRLF +
	"To: =?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@toorop.fr>" + CRLF +
	"Content-Type: text/plain; charset=UTF-8" + CRLF + CRLF +
	"Hello world" + CRLF +
	"line with trailing space         " + CRLF +
	"line with           space         " + CRLF +
	"-- " + CRLF +
	"Toorop" + CRLF + CRLF + CRLF + CRLF + CRLF + CRLF

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
	"Toorop" + CRLF

var bodyRelaxed = "Hello world" + CRLF +
	"line with trailing space" + CRLF +
	"line with space" + CRLF +
	"--" + CRLF +
	"Toorop" + CRLF

var signedRelaxedRelaxed = "DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/relaxed;" + CRLF +
	" s=test; d=tmail.io; l=5; h=from:date:mime-version:received:received;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=byhiFWd0lAM1sqD1tl8S1DZtKNqgiEZp8jrGds6RRydnZkdX9rCPeL0Q5MYWBQ/JmQrml5" + CRLF +
	" pIghLwl/EshDBmNy65O6qO8pSSGgZmM3T7SRLMloex8bnrBJ4KSYcHV46639gVEWcBOKW0" + CRLF +
	" h1djZu2jaTuxGeJzlFVtw3Arf2B93cc=" + CRLF + emailBase

var signedSimpleSimple = "DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=simple/simple;" + CRLF +
	" s=test; d=tmail.io; l=5; h=from:date:mime-version:received:received;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=SoEhlu1Emm2ASqo8jMhz6FIf2nNHt3ouY4Av/pFFEkQ048RqUFP437ap7RbtL2wh0N3Kkm" + CRLF +
	" AKF2TcTLZ++1nalq+djU+/aP4KYQd4RWWFBjkxDzvCH4bvB1M5AGp4Qz9ldmdMQBWOvvSp" + CRLF +
	" DIpJW4XNA/uqLSswtjCYbJsSg9Ywv1o=" + CRLF + emailBase

var signedNoFrom = "DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=simple/simple;" + CRLF +
	" s=test; d=tmail.io; h=from:date:mime-version:received:received;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=SoEhlu1Emm2ASqo8jMhz6FIf2nNHt3ouY4Av/pFFEkQ048RqUFP437ap7RbtL2wh0N3Kkm" + CRLF +
	" AKF2TcTLZ++1nalq+djU+/aP4KYQd4RWWFBjkxDzvCH4bvB1M5AGp4Qz9ldmdMQBWOvvSp" + CRLF +
	" DIpJW4XNA/uqLSswtjCYbJsSg9Ywv1o=" + CRLF + emailBaseNoFrom

var signedMissingFlag = "DKIM-Signature: v=1; q=dns/txt; c=simple/simple;" + CRLF +
	" s=test; d=tmail.io; l=5; h=from:date:mime-version:received:received;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=SoEhlu1Emm2ASqo8jMhz6FIf2nNHt3ouY4Av/pFFEkQ048RqUFP437ap7RbtL2wh0N3Kkm" + CRLF +
	" AKF2TcTLZ++1nalq+djU+/aP4KYQd4RWWFBjkxDzvCH4bvB1M5AGp4Qz9ldmdMQBWOvvSp" + CRLF +
	" DIpJW4XNA/uqLSswtjCYbJsSg9Ywv1o=" + CRLF + emailBase

var signedBadAlgo = "DKIM-Signature: v=1; a=rsa-shasha; q=dns/txt; c=simple/simple;" + CRLF +
	" s=test; d=tmail.io; l=5; h=from:date:mime-version:received:received;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=SoEhlu1Emm2ASqo8jMhz6FIf2nNHt3ouY4Av/pFFEkQ048RqUFP437ap7RbtL2wh0N3Kkm" + CRLF +
	" AKF2TcTLZ++1nalq+djU+/aP4KYQd4RWWFBjkxDzvCH4bvB1M5AGp4Qz9ldmdMQBWOvvSp" + CRLF +
	" DIpJW4XNA/uqLSswtjCYbJsSg9Ywv1o=" + CRLF + emailBase

var signedDouble = "DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=simple/simple;" + CRLF +
	" s=test; d=tmail.io; l=5; h=from:date:mime-version:received:received;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=SoEhlu1Emm2ASqo8jMhz6FIf2nNHt3ouY4Av/pFFEkQ048RqUFP437ap7RbtL2wh0N3Kkm" + CRLF +
	" AKF2TcTLZ++1nalq+djU+/aP4KYQd4RWWFBjkxDzvCH4bvB1M5AGp4Qz9ldmdMQBWOvvSp" + CRLF +
	" DIpJW4XNA/uqLSswtjCYbJsSg9Ywv1o=" + CRLF +
	"DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/relaxed;" + CRLF +
	" s=test; d=tmail.io; l=5; h=from:date:mime-version:received:received;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=byhiFWd0lAM1sqD1tl8S1DZtKNqgiEZp8jrGds6RRydnZkdX9rCPeL0Q5MYWBQ/JmQrml5" + CRLF +
	" pIghLwl/EshDBmNy65O6qO8pSSGgZmM3T7SRLMloex8bnrBJ4KSYcHV46639gVEWcBOKW0" + CRLF +
	" h1djZu2jaTuxGeJzlFVtw3Arf2B93cc=" + CRLF + emailBase

func Test_NewSigOptions(t *testing.T) {
	options := NewSigOptions()
	assert.Equal(t, "rsa-sha256", options.Algo)
	assert.Equal(t, "simple/simple", options.Canonicalization)
}

/*func Test_SignConfig(t *testing.T) {
	email := []byte(emailBase)
	emailToTest := append([]byte(nil), email...)
	options := NewSigOptions()
	err := Sign(&emailToTest, options)
	assert.NotNil(t, err)
	// && err No private key
	assert.EqualError(t, err, ErrSignPrivateKeyRequired.Error())
	options.PrivateKey = privKey
	emailToTest = append([]byte(nil), email...)
	err = Sign(&emailToTest, options)

	// Domain
	assert.EqualError(t, err, ErrSignDomainRequired.Error())
	options.Domain = "toorop.fr"
	emailToTest = append([]byte(nil), email...)
	err = Sign(&emailToTest, options)

	// Selector
	assert.Error(t, err, ErrSignSelectorRequired.Error())
	options.Selector = "default"
	emailToTest = append([]byte(nil), email...)
	err = Sign(&emailToTest, options)
	assert.NoError(t, err)

	// Canonicalization
	options.Canonicalization = "simple/relaxed/simple"
	emailToTest = append([]byte(nil), email...)
	err = Sign(&emailToTest, options)
	assert.EqualError(t, err, ErrSignBadCanonicalization.Error())

	options.Canonicalization = "simple/relax"
	emailToTest = append([]byte(nil), email...)
	err = Sign(&emailToTest, options)
	assert.EqualError(t, err, ErrSignBadCanonicalization.Error())

	options.Canonicalization = "relaxed"
	emailToTest = append([]byte(nil), email...)
	err = Sign(&emailToTest, options)
	assert.NoError(t, err)

	options.Canonicalization = "SiMple/relAxed"
	emailToTest = append([]byte(nil), email...)
	err = Sign(&emailToTest, options)
	assert.NoError(t, err)

	// header
	options.Headers = []string{"toto"}
	emailToTest = append([]byte(nil), email...)
	err = Sign(&emailToTest, options)
	assert.EqualError(t, err, ErrSignHeaderShouldContainsFrom.Error())

	options.Headers = []string{"To", "From"}
	emailToTest = append([]byte(nil), email...)
	err = Sign(&emailToTest, options)
	assert.NoError(t, err)

}

func Test_canonicalize(t *testing.T) {
	email := []byte(emailBase)
	emailToTest := append([]byte(nil), email...)
	options := NewSigOptions()
	options.Headers = []string{"from", "date", "mime-version", "received", "received", "In-Reply-To"}
	// simple/simple
	options.Canonicalization = "simple/simple"
	header, body, err := canonicalize(&emailToTest, options)
	assert.NoError(t, err)
	assert.Equal(t, []byte(headerSimple), header)
	assert.Equal(t, []byte(bodySimple), body)

	// relaxed/relaxed
	emailToTest = append([]byte(nil), email...)
	options.Canonicalization = "relaxed/relaxed"
	header, body, err = canonicalize(&emailToTest, options)
	assert.NoError(t, err)
	assert.Equal(t, []byte(headerRelaxed), header)
	assert.Equal(t, []byte(bodyRelaxed), body)

}
*/
func Test_Sign(t *testing.T) {
	email := []byte(emailBase)
	emailRelaxed := append([]byte(nil), email...)
	options := NewSigOptions()
	options.PrivateKey = privKey
	options.Domain = domain
	options.Selector = selector
	//options.SignatureExpireIn = 3600
	options.BodyLength = 5
	options.Headers = []string{"from", "date", "mime-version", "received", "received"}
	options.AddSignatureTimestamp = false
	options.Canonicalization = "relaxed/relaxed"
	err := Sign(&emailRelaxed, options)
	assert.NoError(t, err)
	assert.Equal(t, []byte(signedRelaxedRelaxed), emailRelaxed)

	options.Canonicalization = "simple/simple"
	emailSimple := append([]byte(nil), email...)
	err = Sign(&emailSimple, options)
	assert.Equal(t, []byte(signedSimpleSimple), emailSimple)

}

func Test_Verify(t *testing.T) {
	// no DKIM header
	email := []byte(emailBase)
	status, err := Verify(&email)
	assert.Equal(t, NOTSIGNED, status)
	assert.Equal(t, ErrDkimHeaderNotFound, err)

	// No From
	email = []byte(signedNoFrom)
	status, err = Verify(&email)
	assert.Equal(t, ErrVerifyBodyHash, err)
	assert.Equal(t, PERMFAIL, status) // cause we use dkheader of the "with from" email

	// missing mandatory 'a' flag
	email = []byte(signedMissingFlag)
	status, err = Verify(&email)
	assert.Error(t, err)
	assert.Equal(t, PERMFAIL, status)
	assert.Equal(t, ErrDkimHeaderMissingRequiredTag, err)

	// missing bad algo
	email = []byte(signedBadAlgo)
	status, err = Verify(&email)
	assert.Equal(t, PERMFAIL, status)
	assert.Equal(t, ErrSignBadAlgo, err)

	// relaxed
	email = []byte(signedRelaxedRelaxed)
	status, err = Verify(&email)
	assert.NoError(t, err)
	assert.Equal(t, SUCCESS, status)

	// simple
	email = []byte(signedSimpleSimple)
	status, err = Verify(&email)
	assert.NoError(t, err)
	assert.Equal(t, SUCCESS, status)
}
