package dkim

import (
	//"fmt"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func privKeyRSA(tb testing.TB) *rsa.PrivateKey {
	block, rest := pem.Decode([]byte(privKey))
	require.NotNil(tb, block)
	require.Empty(tb, rest)

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(tb, err)

	return key
}

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
	"Received: (qmail 21323 invoked from network); 1 May 2015 09:48:39 -0000" + CRLF

var headerRelaxed = "from:=?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@tmail.io>" + CRLF +
	"date:Fri, 1 May 2015 11:48:37 +0200" + CRLF +
	"mime-version:1.0" + CRLF +
	"received:from mail483.ha.ovh.net (b6.ovh.net [213.186.33.56]) by mo51.mail-out.ovh.net (Postfix) with SMTP id A6E22FF8934 for <toorop@toorop.fr>; Mon, 4 May 2015 14:00:47 +0200 (CEST)" + CRLF +
	"received:(qmail 21323 invoked from network); 1 May 2015 09:48:39 -0000" + CRLF

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
	" s=test; d=tmail.io; h=from:date:mime-version:received:received;" + CRLF +
	" bh=4pCY+Pp2c/Wr8fDfBDWKpx3DDsr0CJfSP9H1KYxm5bA=;" + CRLF +
	" b=o0eE20jd8jYqkyxP5rqbfcoUABWZyfrL+l3e1lC0Z+b1Azyrdv+UMmx8L5F57Rhya1SNG2" + CRLF +
	" 9FnMUTwq+u1PmOmB7NwfTq5UCS9UR8wrNffI1mLUsBPFtv+jZtnHzdmR9aCo2HPfBBALC8" + CRLF +
	" jEhQcvm/RaP0aiYJtisLJ86S3k0P1WU=" + CRLF + emailBase

var signedRelaxedRelaxedLength = "DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/relaxed;" + CRLF +
	" s=test; d=tmail.io; l=5; h=from:date:mime-version:received:received;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=byhiFWd0lAM1sqD1tl8S1DZtKNqgiEZp8jrGds6RRydnZkdX9rCPeL0Q5MYWBQ/JmQrml5" + CRLF +
	" pIghLwl/EshDBmNy65O6qO8pSSGgZmM3T7SRLMloex8bnrBJ4KSYcHV46639gVEWcBOKW0" + CRLF +
	" h1djZu2jaTuxGeJzlFVtw3Arf2B93cc=" + CRLF + emailBase

var signedSimpleSimple = "DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=simple/simple;" + CRLF +
	" s=test; d=tmail.io; h=from:date:mime-version:received:received;" + CRLF +
	" bh=ZrMyJ01ZlWHPSzskR7A+4CeBDAd0m8CPny4m15ablao=;" + CRLF +
	" b=nzkqVMlEBL+6m/1AtlFzGV2tHjvfNwFmz9kUDNqphBNSvguv/8KAdqsVheBudJBDHNPrjr" + CRLF +
	" +N57+atXBQX/jng2WAlI5wpQb1TlxLfm8b7SyS1Z7WwSOI0MqaLMhIss4QEVsevaTF1d/1" + CRLF +
	" WcFzOPxn66nnn+CRKaz553tjIn1GeFQ=" + CRLF + emailBase

var signedSimpleSimpleLength = "DKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=simple/simple;" + CRLF +
	" s=test; d=tmail.io; l=5; h=from:subject:date:message-id;" + CRLF +
	" bh=GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=;" + CRLF +
	" b=P4cX4WxnSytfsQ3skg3fYIRljleh2iDJidlr/GPfA4S8pTPNZj4SPhB7CJ6OcbSWwJ6Yer" + CRLF +
	" rHGEmCSEGHJPQm+P12iujJlQ784i34JsBvMC5YAMIQ0DHTNhJRHEyShg1I0B3tqArogdap" + CRLF +
	" qwWLUSFEhPTXglZVhcHIvYZA9X38iF4=" + CRLF + emailBase

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

var signedBadAFlag = "DKIM-Signature: v=1; a=rsashasha sfds; q=dns/txt; c=simple/simple;" + CRLF +
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

var fromGmail = "Return-Path: toorop@gmail.com" + CRLF +
	"Delivered-To: toorop@tmail.io" + CRLF +
	"Received: tmail deliverd local d9ae3ac7c238a50a6e007d207337752eb04038ff; 21 May 2015 19:47:54 +0200" + CRLF +
	"X-Env-From: toorop@gmail.com" + CRLF +
	"Received: from 209.85.217.176 (mail-lb0-f176.google.com.) (mail-lb0-f176.google.com)" + CRLF +
	"	  by 5.196.15.145 (mail.tmail.io.) with ESMTPS; 21 May 2015 19:47:54 +0200; tmail 0.0.8" + CRLF +
	"	; 8008e7eae6f168de88db072ead2b34d0f9194cc5" + CRLF +
	"Authentication-Results: dkim=permfail body hash did not verify" + CRLF +
	"Received: by lbbqq2 with SMTP id qq2so23551469lbb.3" + CRLF +
	"        for <toorop@tmail.io>; Thu, 21 May 2015 10:43:42 -0700 (PDT)" + CRLF +
	"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;" + CRLF +
	"        d=gmail.com; s=20120113;" + CRLF +
	"        h=mime-version:date:message-id:subject:from:to:content-type;" + CRLF +
	"        bh=pwO8HiXlNND4gOHL7bTlAtJFqYruIH1x8q3dAqEw138=;" + CRLF +
	"        b=lh5rCv0Y2uh23DLUv+YsPZEmJMkhxlVRG+aeCmtJ5BpXTbSHldmNv1vbSegCx0LY9K" + CRLF +
	"         l0AEGrpce6YgBk5qRphffEOhANKEkrLesMUyI3yc9JG2J6R19mJ/NyDkT5USZZuI8DOp" + CRLF +
	"         GkRQSIPU4lrj3U27pr6+8I2lANJfINkqbkbBb69068/aPYl2DUMP5SPCFNwB01LHWKqI" + CRLF +
	"         srRDhqRYnAql+PZJVbzrue2HwBflr4ycDzhfZ+Q5BxQZt+TJtzkCUHTGtx5z9JctR93E" + CRLF +
	"         K5hUpKBN6w6GEbj1HDiMsYZOICx3XNDkny8HhFmU0nPjwbHN2C8HslOGZtDPeZWJypSG" + CRLF +
	"         Wuig==" + CRLF +
	"MIME-Version: 1.0" + CRLF +
	"X-Received: by 10.152.206.103 with SMTP id ln7mr3235525lac.40.1432230222503;" + CRLF +
	" Thu, 21 May 2015 10:43:42 -0700 (PDT)" + CRLF +
	"Received: by 10.112.162.129 with HTTP; Thu, 21 May 2015 10:43:42 -0700 (PDT)" + CRLF +
	"Date: Thu, 21 May 2015 19:43:42 +0200" + CRLF +
	"Message-ID: <CADu37kSVY5ZSq9MGjw3yXfn1eNF-hMHjWJyb87JqS4Z79Zksww@mail.gmail.com>" + CRLF +
	"Subject: Test smtpdData" + CRLF +
	"From: =?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@gmail.com>" + CRLF +
	"To: toorop@tmail.io" + CRLF +
	"Content-Type: text/plain; charset=UTF-8" + CRLF + CRLF +
	"Alors ?" + CRLF + CRLF +
	"-- " + CRLF +
	"Toorop" + CRLF +
	"http://www.protecmail.com" + CRLF + CRLF + CRLF

var missingHeaderMail = "Received: tmail deliverd remote 439903a23facd153908f3e17fb487962d01f4b44; 02 Jun 2015 10:00:24 +0000" + CRLF +
	"X-Env-From: toorop@toorop.fr" + CRLF +
	"Received: from 192.168.0.2 (no reverse) by 192.168.0.46 (no reverse) whith" + CRLF +
	"   SMTP; 02 Jun 2015 10:00:23 +0000; tmail 0.0.8;" + CRLF +
	"   d3c348615ef29692ca8bdacb40d0e147c977579c" + CRLF +
	"Message-ID: <1433239223.d3c348615ef29692ca8bdacb40d0e147c977579c@toorop.fr>" + CRLF +
	"Date: Thu, 21 May 2015 19:43:42 +0200" + CRLF +
	"Subject: test" + CRLF + CRLF +
	"test"

func Test_NewSigOptions(t *testing.T) {
	options := NewSigOptions()
	assert.Equal(t, "rsa-sha256", options.Algo)
	assert.Equal(t, "simple/simple", options.Canonicalization)
}

func Test_SignConfig(t *testing.T) {
	email := []byte(emailBase)
	emailToTest := append([]byte(nil), email...)
	options := NewSigOptions()
	err := Sign(&emailToTest, options)
	assert.NotNil(t, err)
	// && err No private key
	assert.EqualError(t, err, ErrSignPrivateKeyRequired.Error())
	options.PrivateKey = []byte(privKey)
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
	header, body, err := canonicalize(&emailToTest, options.Canonicalization, options.Headers)
	assert.NoError(t, err)
	assert.Equal(t, []byte(headerSimple), header)
	assert.Equal(t, []byte(bodySimple), body)

	// relaxed/relaxed
	emailToTest = append([]byte(nil), email...)
	options.Canonicalization = "relaxed/relaxed"
	header, body, err = canonicalize(&emailToTest, options.Canonicalization, options.Headers)
	assert.NoError(t, err)
	assert.Equal(t, []byte(headerRelaxed), header)
	assert.Equal(t, []byte(bodyRelaxed), body)

}

func Test_Sign(t *testing.T) {
	email := []byte(emailBase)
	emailRelaxed := append([]byte(nil), email...)
	options := NewSigOptions()
	options.PrivateKey = []byte(privKey)
	options.Domain = domain
	options.Selector = selector
	//options.SignatureExpireIn = 3600
	options.Headers = []string{"from", "date", "mime-version", "received", "received"}
	options.AddSignatureTimestamp = false

	options.Canonicalization = "relaxed/relaxed"
	err := Sign(&emailRelaxed, options)
	assert.NoError(t, err)
	assert.Equal(t, []byte(signedRelaxedRelaxed), emailRelaxed)

	options.BodyLength = 5
	emailRelaxed = append([]byte(nil), email...)
	err = Sign(&emailRelaxed, options)
	assert.NoError(t, err)
	assert.Equal(t, []byte(signedRelaxedRelaxedLength), emailRelaxed)

	options.BodyLength = 0
	options.Canonicalization = "simple/simple"
	emailSimple := append([]byte(nil), email...)
	err = Sign(&emailSimple, options)
	assert.Equal(t, []byte(signedSimpleSimple), emailSimple)

	options.Headers = []string{"from", "subject", "date", "message-id"}
	memail := []byte(missingHeaderMail)
	err = Sign(&memail, options)
	assert.NoError(t, err)

	options.BodyLength = 5
	options.Canonicalization = "simple/simple"
	emailSimple = append([]byte(nil), email...)
	err = Sign(&emailSimple, options)
	assert.Equal(t, []byte(signedSimpleSimpleLength), emailSimple)

}

func Test_Verify(t *testing.T) {
	resolveTXT := DNSOptLookupTXT(func(name string) ([]string, error) {
		switch name {
		case selector + "._domainkey." + domain:
			return []string{"v=DKIM1; t=y; p=" + pubKey}, nil
		// case "TODO._domainkey.gmail.com":
		// 	return []string{"v=DKIM1; p="}, nil
		default:
			return net.LookupTXT(name)
		}
	})

	// no DKIM header
	email := []byte(emailBase)
	status, err := Verify(&email, resolveTXT)
	assert.Equal(t, NOTSIGNED, status)
	assert.Equal(t, ErrDkimHeaderNotFound, err)

	// No From
	email = []byte(signedNoFrom)
	status, err = Verify(&email, resolveTXT)
	assert.Equal(t, ErrVerifyBodyHash, err)
	assert.Equal(t, TESTINGPERMFAIL, status) // cause we use dkheader of the "with from" email

	// missing mandatory 'a' flag
	email = []byte(signedMissingFlag)
	status, err = Verify(&email, resolveTXT)
	assert.Error(t, err)
	assert.Equal(t, PERMFAIL, status)
	assert.Equal(t, ErrDkimHeaderMissingRequiredTag, err)

	// missing bad algo
	email = []byte(signedBadAlgo)
	status, err = Verify(&email, resolveTXT)
	assert.Equal(t, PERMFAIL, status)
	assert.Equal(t, ErrSignBadAlgo, err)

	// bad a flag
	email = []byte(signedBadAFlag)
	status, err = Verify(&email, resolveTXT)
	assert.Equal(t, PERMFAIL, status)
	assert.Equal(t, ErrSignBadAlgo, err)

	// relaxed
	email = []byte(signedRelaxedRelaxedLength)
	status, err = Verify(&email, resolveTXT)
	assert.NoError(t, err)
	assert.Equal(t, SUCCESS, status)

	// simple
	email = []byte(signedSimpleSimpleLength)
	status, err = Verify(&email, resolveTXT)
	assert.NoError(t, err)
	assert.Equal(t, SUCCESS, status)

	// gmail
	// TODO:
	// Google removed this DNS record some time ago. Someone will have to send an email they're
	// OK with being publicly available, replace the value of the fromGmail var with that, then grab
	// the DNS record indicated in the DKIM signature and update the resolveTXT function to return
	// it when asked. Then this should work.
	// email = []byte(fromGmail)
	// status, err = Verify(&email, resolveTXT)
	// assert.NoError(t, err)
	// assert.Equal(t, SUCCESS, status)

}
