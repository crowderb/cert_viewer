package certs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
)

func OIDToString(oid asn1.ObjectIdentifier) string {
	parts := make([]string, len(oid))
	for i, n := range oid {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(parts, ".")
}

func MapOIDToName(oid asn1.ObjectIdentifier, windowsStyle bool) string {
	// Common OIDs for Subject/Issuer attributes
	oidStr := OIDToString(oid)
	var openssl = map[string]string{
		"2.5.4.3":  "CN",
		"2.5.4.6":  "C",
		"2.5.4.7":  "L",
		"2.5.4.8":  "ST",
		"2.5.4.10": "O",
		"2.5.4.11": "OU",
		"1.2.840.113549.1.9.1": "emailAddress",
		"2.5.4.9":  "street",
		"2.5.4.17": "postalCode",
		"0.9.2342.19200300.100.1.25": "DC",
		"2.5.4.5":  "serialNumber",
	}
	var windows = map[string]string{
		"2.5.4.3":  "Common Name",
		"2.5.4.6":  "Country",
		"2.5.4.7":  "Locality",
		"2.5.4.8":  "State/Province",
		"2.5.4.10": "Organization",
		"2.5.4.11": "Organizational Unit",
		"1.2.840.113549.1.9.1": "E-Mail",
		"2.5.4.9":  "Street",
		"2.5.4.17": "Postal Code",
		"0.9.2342.19200300.100.1.25": "Domain Component",
		"2.5.4.5":  "Serial Number",
	}
	if windowsStyle {
		if v, ok := windows[oidStr]; ok {
			return v
		}
		return oidStr
	}
	if v, ok := openssl[oidStr]; ok {
		return v
	}
	return oidStr
}

func ExtractNameAttributes(attrs []pkix.AttributeTypeAndValue, windowsStyle bool, prefix string) [][]string {
	pairs := [][]string{}
	for _, atv := range attrs {
		name := MapOIDToName(atv.Type, windowsStyle)
		value := fmt.Sprintf("%v", atv.Value)
		label := name
		if prefix != "" {
			label = fmt.Sprintf("%s %s", prefix, name)
		}
		pairs = append(pairs, []string{label, value})
	}
	return pairs
}

func KeyUsageNames(ku x509.KeyUsage) string {
	names := []string{}
	if ku&x509.KeyUsageDigitalSignature != 0 {
		names = append(names, "Digital Signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		names = append(names, "Non Repudiation")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		names = append(names, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		names = append(names, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		names = append(names, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		names = append(names, "Certificate Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		names = append(names, "CRL Sign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		names = append(names, "Encipher Only")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		names = append(names, "Decipher Only")
	}
	return strings.Join(names, ", ")
}

func ExtKeyUsageNames(usages []x509.ExtKeyUsage) string {
	if len(usages) == 0 {
		return ""
	}
	names := make([]string, 0, len(usages))
	for _, u := range usages {
		switch u {
		case x509.ExtKeyUsageAny:
			names = append(names, "Any")
		case x509.ExtKeyUsageServerAuth:
			names = append(names, "TLS Web Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			names = append(names, "TLS Web Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			names = append(names, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			names = append(names, "E-mail Protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			names = append(names, "IPSec End System")
		case x509.ExtKeyUsageIPSECTunnel:
			names = append(names, "IPSec Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			names = append(names, "IPSec User")
		case x509.ExtKeyUsageTimeStamping:
			names = append(names, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			names = append(names, "OCSP Signing")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			names = append(names, "Microsoft Server Gated Crypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			names = append(names, "Netscape Server Gated Crypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			names = append(names, "Microsoft Commercial Code Signing")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			names = append(names, "Microsoft Kernel Code Signing")
		default:
			names = append(names, fmt.Sprintf("Unknown (%d)", u))
		}
	}
	return strings.Join(names, ", ")
}

func NISTCurveName(oidOrName string) string {
	switch oidOrName {
	case "P-256", "prime256v1":
		return "P-256"
	case "P-384", "secp384r1":
		return "P-384"
	case "P-521", "secp521r1":
		return "P-521"
	default:
		return oidOrName
	}
}

func BytesToHexNoSepUpper(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(b) * 2)
	for _, by := range b {
		sb.WriteString(fmt.Sprintf("%02X", by))
	}
	return sb.String()
}

func FormatHex(sum []byte, sep string) string {
	if len(sum) == 0 {
		return ""
	}
	if sep == "" {
		var b strings.Builder
		b.Grow(len(sum) * 2)
		for _, by := range sum {
			b.WriteString(fmt.Sprintf("%02X", by))
		}
		return b.String()
	}
	parts := make([]string, len(sum))
	for i, by := range sum {
		parts[i] = fmt.Sprintf("%02X", by)
	}
	return strings.Join(parts, sep)
}

func FormatSerialWithSep(n *big.Int, sep string) string {
	if n == nil {
		return ""
	}
	hexStr := strings.ToUpper(n.Text(16))
	if len(hexStr)%2 == 1 {
		hexStr = "0" + hexStr
	}
	var b strings.Builder
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 && sep != "" {
			b.WriteString(sep)
		}
		b.WriteString(hexStr[i : i+2])
	}
	return b.String()
}

func NormalizeHexBytesNoSepUpper(b []byte) string {
    return BytesToHexNoSepUpper(b)
}
