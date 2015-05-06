package dkim

import (
	"fmt"
	"strings"
	"time"
)

type DkimHeader struct {
	// Version  This tag defines the version of DKIM
	// specification that applies to the signature record.
	// tag v
	Version string

	// The algorithm used to generate the signature..
	// Verifiers MUST support "rsa-sha1" and "rsa-sha256";
	// Signers SHOULD sign using "rsa-sha256".
	// tag a
	Algorithm string

	// The signature data (base64).
	// Whitespace is ignored in this value and MUST be
	// ignored when reassembling the original signature.
	// In particular, the signing process can safely insert
	// FWS in this value in arbitrary places to conform to line-length
	// limits.
	// tag b
	SignatureData string

	// The hash of the canonicalized body part of the message as
	// limited by the "l=" tag (base64; REQUIRED).
	// Whitespace is ignored in this value and MUST be ignored when reassembling the original
	// signature.  In particular, the signing process can safely insert
	// FWS in this value in arbitrary places to conform to line-length
	// limits.
	// tag bh
	BodyHash string

	// Message canonicalization (plain-text; OPTIONAL, default is
	//"simple/simple").  This tag informs the Verifier of the type of
	// canonicalization used to prepare the message for signing.  It
	// consists of two names separated by a "slash" (%d47) character,
	// corresponding to the header and body canonicalization algorithms,
	// respectively.  These algorithms are described in Section 3.4.  If
	// only one algorithm is named, that algorithm is used for the header
	// and "simple" is used for the body.  For example, "c=relaxed" is
	// treated the same as "c=relaxed/simple".
	// tag c
	MessageCanonicalization string

	// The SDID claiming responsibility for an introduction of a message
	//  into the mail stream (plain-text; REQUIRED).  Hence, the SDID
	//  value is used to form the query for the public key.  The SDID MUST
	// correspond to a valid DNS name under which the DKIM key record is
	// published.  The conventions and semantics used by a Signer to
	// create and use a specific SDID are outside the scope of this
	// specification, as is any use of those conventions and semantics.
	// When presented with a signature that does not meet these
	// requirements, Verifiers MUST consider the signature invalid.
	// Internationalized domain names MUST be encoded as A-labels, as
	// described in Section 2.3 of [RFC5890].
	// tag d
	Domain string

	// Signed header fields (plain-text, but see description; REQUIRED).
	// A colon-separated list of header field names that identify the
	// header fields presented to the signing algorithm.  The field MUST
	// contain the complete list of header fields in the order presented
	// to the signing algorithm.  The field MAY contain names of header
	// fields that do not exist when signed; nonexistent header fields do
	// not contribute to the signature computation (that is, they are
	// treated as the null input, including the header field name, the
	// separating colon, the header field value, and any CRLF
	// terminator).  The field MAY contain multiple instances of a header
	// field name, meaning multiple occurrences of the corresponding
	// header field are included in the header hash.  The field MUST NOT
	// include the DKIM-Signature header field that is being created or
	// verified but may include others.  Folding whitespace (FWS) MAY be
	// included on either side of the colon separator.  Header field
	// names MUST be compared against actual header field names in a
	// case-insensitive manner.  This list MUST NOT be empty.  See
	// Section 5.4 for a discussion of choosing header fields to sign and
	// Section 5.4.2 for requirements when signing multiple instances of
	// a single field.
	// tag h
	Headers []string

	// The Agent or User Identifier (AUID) on behalf of which the SDID is
	// taking responsibility (dkim-quoted-printable; OPTIONAL, default is
	// an empty local-part followed by an "@" followed by the domain from
	// the "d=" tag).
	// The syntax is a standard email address where the local-part MAY be
	// omitted.  The domain part of the address MUST be the same as, or a
	// subdomain of, the value of the "d=" tag.
	// Internationalized domain names MUST be encoded as A-labels, as
	// described in Section 2.3 of [RFC5890].
	// tag i
	Auid string

	// Body length count (plain-text unsigned decimal integer; OPTIONAL,
	// default is entire body).  This tag informs the Verifier of the
	// number of octets in the body of the email after canonicalization
	// included in the cryptographic hash, starting from 0 immediately
	// following the CRLF preceding the body.  This value MUST NOT be
	// larger than the actual number of octets in the canonicalized
	// message body.  See further discussion in Section 8.2.
	// tag l
	BodyLength uint

	// A colon-separated list of query methods used to retrieve the
	// public key (plain-text; OPTIONAL, default is "dns/txt").  Each
	// query method is of the form "type[/options]", where the syntax and
	// semantics of the options depend on the type and specified options.
	// If there are multiple query mechanisms listed, the choice of query
	// mechanism MUST NOT change the interpretation of the signature.
	// Implementations MUST use the recognized query mechanisms in the
	// order presented.  Unrecognized query mechanisms MUST be ignored.
	// Currently, the only valid value is "dns/txt", which defines the
	// DNS TXT resource record (RR) lookup algorithm described elsewhere
	// in this document.  The only option defined for the "dns" query
	// type is "txt", which MUST be included.  Verifiers and Signers MUST
	// support "dns/txt".
	// tag q
	QueryMethods []string

	// The selector subdividing the namespace for the "d=" (domain) tag
	// (plain-text; REQUIRED).
	// Internationalized selector names MUST be encoded as A-labels, as
	// described in Section 2.3 of [RFC5890].
	// tag s
	Selector string

	// Signature Timestamp (plain-text unsigned decimal integer;
	// RECOMMENDED, default is an unknown creation time).  The time that
	// this signature was created.  The format is the number of seconds
	// since 00:00:00 on January 1, 1970 in the UTC time zone.  The value
	// is expressed as an unsigned integer in decimal ASCII.  This value
	// is not constrained to fit into a 31- or 32-bit integer.
	// Implementations SHOULD be prepared to handle values up to at least
	// 10^12 (until approximately AD 200,000; this fits into 40 bits).
	// To avoid denial-of-service attacks, implementations MAY consider
	// any value longer than 12 digits to be infinite.  Leap seconds are
	// not counted.  Implementations MAY ignore signatures that have a
	// timestamp in the future.
	// tag t
	SignatureTimestamp time.Time

	// Signature Expiration (plain-text unsigned decimal integer;
	// RECOMMENDED, default is no expiration).  The format is the same as
	// in the "t=" tag, represented as an absolute date, not as a time
	// delta from the signing timestamp.  The value is expressed as an
	// unsigned integer in decimal ASCII, with the same constraints on
	// the value in the "t=" tag.  Signatures MAY be considered invalid
	// if the verification time at the Verifier is past the expiration
	// date.  The verification time should be the time that the message
	// was first received at the administrative domain of the Verifier if
	// that time is reliably available; otherwise, the current time
	// should be used.  The value of the "x=" tag MUST be greater than
	// the value of the "t=" tag if both are present.
	//tag x
	SignatureExpiration time.Time

	// Copied header fields (dkim-quoted-printable, but see description;
	// OPTIONAL, default is null).  A vertical-bar-separated list of
	// selected header fields present when the message was signed,
	// including both the field name and value.  It is not required to
	// include all header fields present at the time of signing.  This
	// field need not contain the same header fields listed in the "h="
	// tag.  The header field text itself must encode the vertical bar
	// ("|", %x7C) character (i.e., vertical bars in the "z=" text are
	// meta-characters, and any actual vertical bar characters in a
	// copied header field must be encoded).  Note that all whitespace
	// must be encoded, including whitespace between the colon and the
	// header field value.  After encoding, FWS MAY be added at arbitrary
	// locations in order to avoid excessively long lines; such
	// whitespace is NOT part of the value of the header field and MUST
	// be removed before decoding.
	// The header fields referenced by the "h=" tag refer to the fields
	// in the [RFC5322] header of the message, not to any copied fields
	// in the "z=" tag.  Copied header field values are for diagnostic
	// use.
	// tag z
	CopiedHeaderFileds []string
}

// NewDkimHeaderBySigOptions return a new DkimHeader initioalized with sigOptions value
func NewDkimHeaderBySigOptions(options sigOptions) *DkimHeader {
	h := new(DkimHeader)
	h.Version = "1"
	h.Algorithm = options.Algo
	h.MessageCanonicalization = options.Canonicalization
	h.Domain = options.Domain
	h.Headers = options.Headers
	h.Auid = options.Auid
	h.BodyLength = options.BodyLength
	h.QueryMethods = options.QueryMethods
	h.Selector = options.Selector
	if options.AddSignatureTimestamp {
		h.SignatureTimestamp = time.Now()
	}
	if options.SignatureExpireIn > 0 {
		fmt.Println(options.SignatureExpireIn)
		h.SignatureExpiration = time.Now().Add(time.Duration(options.SignatureExpireIn) * time.Second)
	}
	h.CopiedHeaderFileds = options.CopiedHeaderFileds
	return h
}

// GetHeaderBase return base header for signers
// Todo: some refactoring...
func (d *DkimHeader) GetHeaderBase(bodyHash string) string {
	h := "DKIM-Signature: v=" + d.Version + "; a=" + d.Algorithm + "; q=" + strings.Join(d.QueryMethods, ":") + "; c=" + d.MessageCanonicalization + ";" + CRLF + TAB
	subh := "s=" + d.Selector + ";"
	if len(subh)+len(d.Domain)+4 > MaxHeaderLineLength {
		h += subh + FWS
		subh = ""
	}
	subh += " d=" + d.Domain + ";"

	// Auid
	if len(d.Auid) != 0 {
		if len(subh)+len(d.Auid)+4 > MaxHeaderLineLength {
			h += subh + FWS
			subh = ""
		}
		subh += " i=" + d.Auid + ";"
	}

	/*h := "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=tmail.io; i=@tmail.io;" + FWS
	subh := "q=dns/txt; s=test;"*/

	// signature timestamp
	if !d.SignatureTimestamp.IsZero() {
		ts := d.SignatureTimestamp.Unix()
		if len(subh)+14 > MaxHeaderLineLength {
			h += subh + FWS
			subh = ""
		}
		subh += " t=" + fmt.Sprintf("%d", ts) + ";"
	}
	if len(subh)+len(d.Domain)+4 > MaxHeaderLineLength {
		h += subh + FWS
		subh = ""
	}

	// Expiration
	if !d.SignatureExpiration.IsZero() {
		ts := d.SignatureExpiration.Unix()
		if len(subh)+14 > MaxHeaderLineLength {
			h += subh + FWS
			subh = ""
		}
		subh += " x=" + fmt.Sprintf("%d", ts) + ";"
	}

	// Headers
	if len(subh)+len(d.Headers)+4 > MaxHeaderLineLength {
		h += subh + FWS
		subh = ""
	}
	subh += " h="
	for _, header := range d.Headers {
		if len(subh)+len(header)+1 > MaxHeaderLineLength {
			h += subh + FWS
			subh = ""
		}
		subh += header + ":"
	}
	subh = subh[:len(subh)-1] + ";"

	// BodyHash
	if len(subh)+5+len(bodyHash) > MaxHeaderLineLength {
		h += subh + FWS
		subh = ""
	} else {
		subh += " "
	}
	subh += "bh="
	l := len(subh)
	for _, c := range bodyHash {
		subh += string(c)
		l++
		if l >= MaxHeaderLineLength {
			h += subh + FWS
			subh = ""
			l = 0
		}
	}
	h += subh + ";" + FWS + "b="

	return h
}

//'test._domainkey.tmail.io:v=DKIM1;k=rsa;s=email;h=sha256;t=y;p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNUXO+Qsl1tw+GjrqFajz0ERSEUs1FHSL/+udZRWn1Atw8gz0+tcGqhWChBDeU9gY5sKLEAZnX3FjC/T/IbqeiSM68kS5vLkzRI84eiJrm3+IieUqIIicsO+WYxQs+JgVx5XhpPjX4SQjHtwEC2xKkWnEv+VPgO1JWdooURcSC6QIDAQAB':300::
