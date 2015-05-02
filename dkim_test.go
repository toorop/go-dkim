package dkim

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

var email = `Received: (qmail 28277 invoked from network); 1 May 2015 09:43:37 -0000
Received: (qmail 21323 invoked from network); 1 May 2015 09:48:39 -0000
MIME-Version: 1.0
Date: Fri, 1 May 2015 11:48:37 +0200
Message-ID: <CADu37kTXBeNkJdXc4bSF8DbJnXmNjkLbnswK6GzG_2yn7U7P6w@tmail.io>
Subject: Test DKIM
From: =?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@gmail.com>
To: =?UTF-8?Q?St=C3=A9phane_Depierrepont?= <toorop@toorop.fr>
Content-Type: text/plain; charset=UTF-8


Hello world
-- 
Toorop`

func Test_NewSigOptions(t *testing.T) {
	options := NewSigOptions()
	assert.Equal(t, "rsa-sha256", options.Algo)
	assert.Equal(t, "simple/simple", options.Canonicalization)
}

func Test_Sign(t *testing.T) {
	emailReader := bytes.NewReader([]byte(email))
	options := NewSigOptions()
	_, err := Sign(emailReader, options)
	assert.NotNil(t, err)
	// && err No private key
	assert.Error(t, ErrConfigNoPrivateKey)
	options.PrivateKey = "toto"
	_, err = Sign(emailReader, options)
	// No
	assert.Error(t, ErrConfigNoDomain)

}
