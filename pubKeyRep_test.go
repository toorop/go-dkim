package dkim

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPubKeyRep(t *testing.T) {
	t.Parallel()

	type testCase struct {
		Name         string
		Txt          string
		Expect       *PubKeyRep
		VerifyOutput verifyOutput
		Err          error
	}

	testCases := []testCase{
		{
			Name: "only required",
			Txt:  "p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name:         "empty record",
			Txt:          "",
			VerifyOutput: PERMFAIL,
			Err:          ErrVerifyNoKey,
		},

		// v=
		{
			Name:         "version not first",
			Txt:          "p=" + pubKey + "; v=DKIM1",
			VerifyOutput: PERMFAIL,
			Err:          ErrVerifyTagVMustBeTheFirst,
		},
		{
			Name:         "wrong version",
			Txt:          "v=DKIM2; p=" + pubKey,
			VerifyOutput: PERMFAIL,
			Err:          ErrVerifyVersionMusBeDkim1,
		},

		// p=
		{
			Name:         "no key",
			Txt:          "v=DKIM1",
			VerifyOutput: PERMFAIL,
			Err:          ErrVerifyNoKey,
		},
		{
			Name:         "key revoked",
			Txt:          "v=DKIM1; p=",
			VerifyOutput: PERMFAIL,
			Err:          ErrVerifyRevokedKey,
		},
		{
			Name:         "key invalid",
			Txt:          "v=DKIM1; p=badBase64",
			VerifyOutput: PERMFAIL,
			Err:          ErrVerifyBadKey,
		},

		// h=
		{
			Name: "all supported hashes",
			Txt:  "v=DKIM1; h=sha1:sha256; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "sha256 only",
			Txt:  "v=DKIM1; h=sha256; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "sha1 only",
			Txt:  "v=DKIM1; h=sha1; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "unsupported hash",
			Txt:  "v=DKIM1; h=sha512; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "unsupported hash with supported hash",
			Txt:  "v=DKIM1; h=sha256:sha512; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "empty hash list",
			Txt:  "v=DKIM1; h=; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},

		// k=
		{
			Name: "key type rsa",
			Txt:  "v=DKIM1; k=rsa; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name:         "unsupported key type",
			Txt:          "v=DKIM1; k=dsa; p=" + pubKey,
			VerifyOutput: PERMFAIL,
			Err:          ErrVerifyBadKeyType,
		},
		{
			Name:         "empty key type",
			Txt:          "v=DKIM1; k=; p=" + pubKey,
			VerifyOutput: PERMFAIL,
			Err:          ErrVerifyBadKeyType,
		},

		// n=
		{
			Name: "with note",
			Txt:  "v=DKIM1; n=a note; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				Note:        "a note",
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "with note (qp)",
			Txt:  "v=DKIM1; n=a note=3B encoded as quoted printable; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				Note:        "a note; encoded as quoted printable",
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "with note (bad qp)",
			Txt:  "v=DKIM1; n=a note =! with invalid quoted printable; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				Note:        "a note =! with invalid quoted printable",
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "empty note",
			Txt:  "v=DKIM1; n=; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},

		// s=
		{
			Name: "any service",
			Txt:  "v=DKIM1; s=*; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "email service",
			Txt:  "v=DKIM1; s=email; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"email"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "all services",
			Txt:  "v=DKIM1; s=* : email; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all", "email"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "unsupported service",
			Txt:  "v=DKIM1; s=unknown; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "unsupported service with supported service",
			Txt:  "v=DKIM1; s=unknown:email; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"email"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "empty services",
			Txt:  "v=DKIM1; s=; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},

		// t=
		{
			Name: "testing mode",
			Txt:  "v=DKIM1; t=y; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				PubKey:      privKeyRSA(t).PublicKey,
				FlagTesting: true,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "strict mode",
			Txt:  "v=DKIM1; t=s; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:      "DKIM1",
				HashAlgo:     []string{"sha1", "sha256"},
				KeyType:      "rsa",
				ServiceType:  []string{"all"},
				PubKey:       privKeyRSA(t).PublicKey,
				FlagIMustBeD: true,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "both test flags",
			Txt:  "v=DKIM1; t=y : s; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:      "DKIM1",
				HashAlgo:     []string{"sha1", "sha256"},
				KeyType:      "rsa",
				ServiceType:  []string{"all"},
				PubKey:       privKeyRSA(t).PublicKey,
				FlagTesting:  true,
				FlagIMustBeD: true,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "include invalid test flag",
			Txt:  "v=DKIM1; t=y:s:?; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:      "DKIM1",
				HashAlgo:     []string{"sha1", "sha256"},
				KeyType:      "rsa",
				ServiceType:  []string{"all"},
				PubKey:       privKeyRSA(t).PublicKey,
				FlagTesting:  true,
				FlagIMustBeD: true,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "invalid test flag",
			Txt:  "v=DKIM1; t=?; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
		{
			Name: "empty test flags",
			Txt:  "v=DKIM1; t=; p=" + pubKey,
			Expect: &PubKeyRep{
				Version:     "DKIM1",
				HashAlgo:    []string{"sha1", "sha256"},
				KeyType:     "rsa",
				ServiceType: []string{"all"},
				PubKey:      privKeyRSA(t).PublicKey,
			},
			VerifyOutput: SUCCESS,
		},
	}

	for _, tc := range testCases {
		// Subtests are actually run in goroutines, so make sure to capture the loop var
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			pubKeyRep, vo, err := NewPubKeyResp(tc.Txt)
			if tc.Err != nil {
				assert.EqualError(t, err, tc.Err.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.VerifyOutput, vo)
			assert.EqualValues(t, tc.Expect, pubKeyRep)
		})
	}
}
