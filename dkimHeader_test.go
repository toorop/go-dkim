package dkim

import (
	"testing"

	"github.com/go-test/deep"
)

func Test_GetHeader(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *DKIMHeader
		wantErr bool
	}{
		{
			name:  "Signed relaxed with length",
			input: signedRelaxedRelaxedLength,
			want: &DKIMHeader{
				Version:                 "1",
				Algorithm:               "rsa-sha256",
				QueryMethods:            []string{"dns/txt"},
				MessageCanonicalization: "relaxed/relaxed",
				Selector:                "test",
				Domain:                  "tmail.io",
				Auid:                    "@tmail.io",
				BodyLength:              5,
				Headers:                 []string{"from", "date", "mime-version", "received", "received"},
				BodyHash:                "GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=",
				SignatureData: "byhiFWd0lAM1sqD1tl8S1DZtKNqgiEZp8jrGds6RRydnZkdX9rCPeL0Q5MYWBQ/JmQrml5" +
					"pIghLwl/EshDBmNy65O6qO8pSSGgZmM3T7SRLMloex8bnrBJ4KSYcHV46639gVEWcBOKW0" +
					"h1djZu2jaTuxGeJzlFVtw3Arf2B93cc=",
			},
		},
		{
			name:    "No signature",
			input:   bodySimple,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email := []byte(tt.input)
			got, err := GetHeader(&email)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := deep.Equal(tt.want, got); diff != nil {
				t.Error(diff)
			}
		})
	}
}
