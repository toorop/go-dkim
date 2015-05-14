# go-dkim
DKIM package for Golang

[![GoDoc](https://godoc.org/github.com/Toorop/go-dkim?status.svg)](https://godoc.org/github.com/Toorop/go-dkim)

## Getting started

### Install
```
 	go get https://github.com/toorop/go-dkim
```
### Sign email

```go
import (
	dkim "github.com/toorop/go-dkim"
)

func main(){
	// email is the email to sign (byte slice)
	// privateKey the private key (pem encoded, byte slice )	
	options := dkim.NewSigOptions()
	options.PrivateKey = privateKey
	options.Domain = "mydomain.tld"
	options.Selector = "myselector"
	options.SignatureExpireIn = 3600
	options.BodyLength = 50
	options.Headers = []string{"from", "date", "mime-version", "received", "received"}
	options.AddSignatureTimestamp = true
	options.Canonicalization = "relaxed/relaxed"
	err := dkim.Sign(&email, options)
	// handle err..

	// And... that's it, 'email' is signed ! Amazing© !!!
}
```

### Verify
```go
import (
	dkim "github.com/toorop/go-dkim"
)

func main(){
	// email is the email to verify (byte slice)
	status, err := Verify(&email)
	// handle status, err (see godoc for status)
}
```

