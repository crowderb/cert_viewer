package certs

import (
	"crypto/x509"
	"encoding/asn1"

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var oidExtensionAuthorityKeyID = asn1.ObjectIdentifier{2, 5, 29, 35}

// AuthorityKeyIdentifierKeyID returns the keyIdentifier octets from the Authority Key
// Identifier extension. It prefers x509.Certificate.AuthorityKeyId and otherwise
// parses the raw extension value. This still runs when the extension is marked critical
// (crypto/x509 refuses those when populating AuthorityKeyId during parse).
func AuthorityKeyIdentifierKeyID(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	if len(cert.AuthorityKeyId) > 0 {
		return cert.AuthorityKeyId
	}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidExtensionAuthorityKeyID) {
			continue
		}
		val := cryptobyte.String(ext.Value)
		var akid cryptobyte.String
		if !val.ReadASN1(&akid, casn1.SEQUENCE) {
			continue
		}
		if akid.PeekASN1Tag(casn1.Tag(0).ContextSpecific()) {
			if !akid.ReadASN1(&akid, casn1.Tag(0).ContextSpecific()) {
				continue
			}
			return []byte(akid)
		}
	}
	return nil
}
