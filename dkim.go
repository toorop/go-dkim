package dkim

import (
	"bytes"
	"container/list"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	//"fmt"
	"hash"
	//"io/ioutil"
	//"net"
	"regexp"
	"strings"
)

const (
	CRLF                = "\r\n"
	TAB                 = " "
	FWS                 = CRLF + TAB
	MaxHeaderLineLength = 70
)

type VerifyOutput int

const (
	SUCCESS VerifyOutput = 1 + iota
	PERMFAIL
	TEMPFAIL
	NOTSIGNED
)

// sigOptions represents signing options
type sigOptions struct {

	// DKIM version (default 1)
	Version uint

	// Private key used for signing (required)
	PrivateKey string

	// Domain (required)
	Domain string

	// Selector (required)
	Selector string

	// The Agent of User IDentifier
	Auid string

	// Message canonicalization (plain-text; OPTIONAL, default is
	// "simple/simple").  This tag informs the Verifier of the type of
	// canonicalization used to prepare the message for signing.
	Canonicalization string

	// The algorithm used to generate the signature
	//"rsa-sha1" or "rsa-sha256"
	Algo string

	// Signed header fields
	Headers []string

	// Body length count( if set to 0 this tag is ommited in Dkim header)
	BodyLength uint

	// Query Methods used to retrieve the public key
	QueryMethods []string

	// Add a signature timestamp
	AddSignatureTimestamp bool

	// Time validity of the signature (0=never)
	SignatureExpireIn uint64

	// CopiedHeaderFileds
	CopiedHeaderFields []string
}

// NewSigOption returns new sigoption with some defaults value
func NewSigOptions() sigOptions {
	return sigOptions{
		Version:               1,
		Canonicalization:      "simple/simple",
		Algo:                  "rsa-sha256",
		Headers:               []string{"from"},
		BodyLength:            0,
		QueryMethods:          []string{"dns/txt"},
		AddSignatureTimestamp: true,
		SignatureExpireIn:     0,
	}
}

// Sign signs an email
func Sign(email *[]byte, options sigOptions) error {
	var privateKey *rsa.PrivateKey

	// PrivateKey
	if options.PrivateKey == "" {
		return ErrSignPrivateKeyRequired
	}
	d, _ := pem.Decode([]byte(options.PrivateKey))
	key, err := x509.ParsePKCS1PrivateKey(d.Bytes)
	if err != nil {
		return ErrCandNotParsePrivateKey
	}
	privateKey = key

	// Domain required
	if options.Domain == "" {
		return ErrSignDomainRequired
	}

	// Selector required
	if options.Selector == "" {
		return ErrSignSelectorRequired
	}

	// Canonicalization
	options.Canonicalization, err = validateCanonicalization(strings.ToLower(options.Canonicalization))
	if err != nil {
		return err
	}

	// Algo
	options.Algo = strings.ToLower(options.Algo)
	if options.Algo != "rsa-sha1" && options.Algo != "rsa-sha256" {
		return ErrSignBadAlgo
	}

	// Header must contain "from"
	// normalize -> strtlower
	hasFrom := false
	for i, h := range options.Headers {
		h = strings.ToLower(h)
		options.Headers[i] = h
		if h == "from" {
			hasFrom = true
		}
	}
	if !hasFrom {
		return ErrSignHeaderShouldContainsFrom
	}

	// Normalize
	headers, body, err := canonicalize(email, options.Canonicalization, options.Headers)
	if err != nil {
		return err
	}

	// hash body
	var h2 hash.Hash
	var h3 crypto.Hash
	signHash := strings.Split(options.Algo, "-")
	if signHash[1] == "sha1" {
		//h1 = sha1.New()
		h2 = sha1.New()
		h3 = crypto.SHA1
	} else {
		//h1 = sha256.New()
		h2 = sha256.New()
		h3 = crypto.SHA256
	}

	bodyHash, err := getBodyHash(&body, signHash[1], options.BodyLength)
	if err != nil {
		return err
	}

	// Get dkim header base
	dkimHeader := NewDkimHeaderBySigOptions(options)
	dHeader := dkimHeader.GetHeaderBaseForSigning(bodyHash)

	canonicalizations := strings.Split(options.Canonicalization, "/")
	dHeaderCanonicalized, err := canonicalizeHeader(dHeader, canonicalizations[0])
	if err != nil {
		return err
	}
	headers = append(headers, []byte(dHeaderCanonicalized)...)
	headers = bytes.TrimRight(headers, " \r\n")

	// sign
	h2.Write(headers)
	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, h3, h2.Sum(nil))
	if err != nil {
		return err
	}
	sig64 := base64.StdEncoding.EncodeToString(sig)

	// add to DKIM-Header
	subh := ""
	l := len(subh)
	for _, c := range sig64 {
		subh += string(c)
		l++
		if l >= MaxHeaderLineLength {
			dHeader += subh + FWS
			subh = ""
			l = 0
		}
	}
	dHeader += subh + CRLF
	*email = append([]byte(dHeader), *email...)
	return nil
}

// verify verifies an email an return
// state: SUCCESS or PERMFAIL or TEMPFAIL or NOTSIGNED
// msg: a complementary message (if needed)
// error: if an error occurs during verification
func Verify(email *[]byte) (VerifyOutput, error) {
	// parse email
	dkimHeader, err := NewFromEmail(email)
	if err != nil {
		if err == ErrDkimHeaderNotFound {
			return NOTSIGNED, ErrDkimHeaderNotFound
		} else {
			return PERMFAIL, err
		}
	}

	// Normalize
	_, body, err := canonicalize(email, dkimHeader.MessageCanonicalization, dkimHeader.Headers)
	if err != nil {
		return PERMFAIL, err
	}
	sigHash := strings.Split(dkimHeader.Algorithm, "-")

	// expired ? TODO

	// get body hash
	bodyHash, err := getBodyHash(&body, sigHash[0], dkimHeader.BodyLength)
	if err != nil {
		return PERMFAIL, err
	}
	println(bodyHash)
	if bodyHash != dkimHeader.BodyHash {
		return PERMFAIL, ErrVerifyBodyHash
	}

	// we do not set quesry method because if it's other validation failed earlier
	pubKey, verifyOutputOnError, err := newPubKeyFromDnsTxt(dkimHeader.Selector, dkimHeader.Domain)
	if err != nil {
		return verifyOutputOnError, err
	}
	println(pubKey)

	return SUCCESS, nil
}

// canonicalize returns canonicalized version of header and body
func canonicalize(email *[]byte, cano string, h []string) (headers, body []byte, err error) {
	body = []byte{}
	rxReduceWS := regexp.MustCompile(`[ \t]+`)

	// TODO: \n -> \r\n
	parts := bytes.SplitN(*email, []byte{13, 10, 13, 10}, 2)

	if len(parts) != 2 {
		return headers, body, ErrBadMailFormat
	}

	// Empty body
	if len(parts[1]) == 0 {
		parts[1] = []byte{13, 10}
	}

	canonicalizations := strings.Split(cano, "/")

	// canonicalyze header
	headersList := list.New()
	currentHeader := []byte{}
	for _, line := range bytes.SplitAfter(parts[0], []byte{10}) {
		if line[0] == 32 || line[0] == 9 {
			if len(currentHeader) == 0 {
				return headers, body, ErrBadMailFormatHeaders
			}
			currentHeader = append(currentHeader, line...)
		} else {
			// New header, save current if exists
			if len(currentHeader) != 0 {
				headersList.PushBack(string(currentHeader))
				currentHeader = []byte{}

			}
			currentHeader = append(currentHeader, line...)
		}
	}

	// pour chaque header a conserver on traverse tous les headers dispo
	// If multi instance of a field we must keep it from the bottom to the top
	var match *list.Element
	headersToKeepList := list.New()

	for _, headerToKeep := range h {
		match = nil
		headerToKeepToLower := strings.ToLower(headerToKeep)
		for e := headersList.Front(); e != nil; e = e.Next() {
			t := strings.Split(e.Value.(string), ":")
			if strings.ToLower(t[0]) == headerToKeepToLower {
				match = e
			}
		}
		if match != nil {
			headersToKeepList.PushBack(match.Value.(string))
			headersList.Remove(match)
		} else {
			headersToKeepList.PushBack(headerToKeep + ":\r\n")
		}
	}

	//if canonicalizations[0] == "simple" {
	for e := headersToKeepList.Front(); e != nil; e = e.Next() {
		cHeader, err := canonicalizeHeader(e.Value.(string), canonicalizations[0])
		if err != nil {
			return headers, body, err
		}
		headers = append(headers, []byte(cHeader)...)
	}
	// canonicalyze body
	if canonicalizations[1] == "simple" {
		// simple
		// The "simple" body canonicalization algorithm ignores all empty lines
		// at the end of the message body.  An empty line is a line of zero
		// length after removal of the line terminator.  If there is no body or
		// no trailing CRLF on the message body, a CRLF is added.  It makes no
		// other changes to the message body.  In more formal terms, the
		// "simple" body canonicalization algorithm converts "*CRLF" at the end
		// of the body to a single "CRLF".
		// Note that a completely empty or missing body is canonicalized as a
		// single "CRLF"; that is, the canonicalized length will be 2 octets.
		body = bytes.TrimRight(parts[1], "\r\n")
		body = append(body, []byte{13, 10}...)
	} else {
		// relaxed
		// Ignore all whitespace at the end of lines.  Implementations
		// MUST NOT remove the CRLF at the end of the line.
		// Reduce all sequences of WSP within a line to a single SP
		// character.
		// Ignore all empty lines at the end of the message body.  "Empty
		// line" is defined in Section 3.4.3.  If the body is non-empty but
		// does not end with a CRLF, a CRLF is added.  (For email, this is
		// only possible when using extensions to SMTP or non-SMTP transport
		// mechanisms.)
		parts[1] = rxReduceWS.ReplaceAll(parts[1], []byte(" "))
		for _, line := range bytes.SplitAfter(parts[1], []byte{10}) {
			line = bytes.TrimRight(line, " \r\n")

			if len(line) != 0 {
				body = append(body, line...)
				body = append(body, []byte{13, 10}...)
			}
		}
	}
	return
}

// canonicalizeHeader returns canonicalized version of header
func canonicalizeHeader(header string, algo string) (string, error) {
	//rxReduceWS := regexp.MustCompile(`[ \t]+`)
	if algo == "simple" {
		// The "simple" header canonicalization algorithm does not change header
		// fields in any way.  Header fields MUST be presented to the signing or
		// verification algorithm exactly as they are in the message being
		// signed or verified.  In particular, header field names MUST NOT be
		// case folded and whitespace MUST NOT be changed.
		return header, nil
	} else if algo == "relaxed" {
		// The "relaxed" header canonicalization algorithm MUST apply the
		// following steps in order:

		// Convert all header field names (not the header field values) to
		// lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC".

		// Unfold all header field continuation lines as described in
		// [RFC5322]; in particular, lines with terminators embedded in
		// continued header field values (that is, CRLF sequences followed by
		// WSP) MUST be interpreted without the CRLF.  Implementations MUST
		// NOT remove the CRLF at the end of the header field value.

		// Convert all sequences of one or more WSP characters to a single SP
		// character.  WSP characters here include those before and after a
		// line folding boundary.

		// Delete all WSP characters at the end of each unfolded header field
		// value.

		// Delete any WSP characters remaining before and after the colon
		// separating the header field name from the header field value.  The
		// colon separator MUST be retained.
		kv := strings.SplitN(header, ":", 2)
		if len(kv) != 2 {
			return header, ErrBadMailFormatHeaders
		}
		k := strings.ToLower(kv[0])
		k = strings.TrimSpace(k)
		v := removeFWS(kv[1])
		//v = rxReduceWS.ReplaceAllString(v, " ")
		//v = strings.TrimSpace(v)
		return k + ":" + v + CRLF, nil
	}
	return header, ErrSignBadCanonicalization
}

// getBodyHash return the hash (bas64encoded) of the body
func getBodyHash(body *[]byte, algo string, bodyLength uint) (string, error) {
	var h hash.Hash
	if algo == "sha1" {
		h = sha1.New()
	} else {
		h = sha256.New()
	}
	toH := *body
	// if l tag (body length)
	if bodyLength != 0 {
		if uint(len(toH)) < bodyLength {
			return "", ErrBadDKimTagLBodyTooShort
		}
		toH = toH[0:bodyLength]
	}

	h.Write(toH)
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// removeFWS removes all FWS from string
func removeFWS(in string) string {
	rxReduceWS := regexp.MustCompile(`[ \t]+`)
	out := strings.Replace(in, "\n", "", -1)
	out = strings.Replace(out, "\r", "", -1)
	out = rxReduceWS.ReplaceAllString(out, " ")
	return strings.TrimSpace(out)
}

// validateCanonicalization validate canonicalization (c flag)
func validateCanonicalization(cano string) (string, error) {
	p := strings.Split(cano, "/")
	if len(p) > 2 {
		return "", ErrSignBadCanonicalization
	}
	if len(p) == 1 {
		cano = cano + "/simple"
	}
	for _, c := range p {
		if c != "simple" && c != "relaxed" {
			return "", ErrSignBadCanonicalization
		}
	}
	return cano, nil
}
