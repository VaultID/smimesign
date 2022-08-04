package cms

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"testing"
)

type TestSigner struct {
	Instance        *crypto.Signer
	certificate     *x509.Certificate
	signatureDigest []byte
}

// Interface crypto.Signer
func (ts TestSigner) Public() crypto.PublicKey {
	return ts.certificate.PublicKey
}

// Interface crypto.Signer
func (ts TestSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return ts.signatureDigest, nil
}

func TestOutTimestamp(t *testing.T) {
	rawSignature := "RBnP3iKxbzHqcX6+JLhMrAVpEqAyi85STbbaOlwg7zc7zYtmp/se5BjAzxq25ATL0UBma9cGCYfTsP9P3abzKfDtIq71OLHNnL2pqehwelLSW+qNdKIKe421P/wNigIuWjW1/h4msJ9oqbDCWtt14Kpvw760nQOmQYcv23hHi1d3WpAiki23wBVVwXn40mmlYzqC+Qh3GDw47hW4LXGTI2oG8yetnO7Cu40tQXJBTaJuKMrW6aSzXDkhijogkORe0FAsLXimFKSsiwcF24pTeZnXl7sF96GUfGzpH2mOo5A3Cu4WyHNj6LEua9jJI8vyfUuY9I7k9xtiMm9u/3g2DA=="
	pemCertificate := `-----BEGIN CERTIFICATE-----
MIIHAjCCBOqgAwIBAgIIET0YCBM7vrwwDQYJKoZIhvcNAQELBQAwgYAxCzAJBgNV
BAYTAkJSMRMwEQYDVQQKEwpJQ1AtQnJhc2lsMRkwFwYDVQQLExBBQyBSQUlaIHRl
c3RlIHYyMRswGQYDVQQLExJBQyBTT0xVVEkgdGVzdGUgdjIxJDAiBgNVBAMTG0FD
IFNPTFVUSSBNdWx0aXBsYSB0ZXN0ZSB2MjAeFw0xODA5MTEwOTM5MDNaFw0xOTA4
MTMxNTM2MDBaMIHKMQswCQYDVQQGEwJCUjETMBEGA1UEChMKSUNQLUJyYXNpbDE0
MDIGA1UECxMrQXV0b3JpZGFkZSBDZXJ0aWZpY2Fkb3JhIFJhaXogQnJhc2lsZWly
YSB2MjESMBAGA1UECxMJQUMgU09MVVRJMRswGQYDVQQLExJBQyBTT0xVVEkgTXVs
dGlwbGExGjAYBgNVBAsTEUNlcnRpZmljYWRvIFBGIEExMSMwIQYDVQQDExpMVUNJ
QU5BIE1BQ0lFTDo0ODA5MDc3NzA1ODCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAL7xN6DYbSSUsDHrNJMOrCmwMwdv4uXvOSV7tbBEFdrGHwOYwhkxkM6R
dATJ//HORKsuwL3MuQ0mmsG1s0AcjY6q1T81rjMFcbA4vjZMn4EsmlVZD3YQMUej
JA0bBFYi3aMBQr5XovT8CTj7+3JTCv24y8OYdnwHYgTpQ2bt65ZRGJEK1kHKJ6Kf
aC9L1MZDm5mj59y3/J1W4u7LgdJ2jPNI1MswamSgE2blGII/7flUuubuH85+5hv/
2FYlUFiVnNeT4VqYevhdqf8u005iHPsQnWW+ydcWN+pA376v18F2JUI+MLy2+8JN
aLLRl8x7THLiCyPdi3GJJ6/Vlu1orcsCAwEAAaOCAjIwggIuMF4GCCsGAQUFBwEB
BFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL2NjZDIuYWNzb2x1dGkuY29tLmJyL3Rl
c3Rlcy9hYy1zb2x1dGktbXVsdGlwbGEtdGVzdGUtdjIucDdiMB0GA1UdDgQWBBSM
INEZ7BMfQYZ1KeTfkSIn835fwTAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFDtWIBjs
Ai0GpbRtLIh63jV5PUhyMF4GA1UdIARXMFUwUwYGYEwBAgEmMEkwRwYIKwYBBQUH
AgEWO2h0dHBzOi8vY2NkLmFjc29sdXRpLmNvbS5ici9kb2NzL2RwYy1hYy1zb2x1
dGktbXVsdGlwbGEucGRmMFMGA1UdHwRMMEowSKBGoESGQmh0dHA6Ly9jY2QyLmFj
c29sdXRpLmNvbS5ici90ZXN0ZXMvYWMtc29sdXRpLW11bHRpcGxhLXRlc3RlLXYy
LmNybDAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUF
BwMEMIGcBgNVHREEgZQwgZGBHGx1Y2lhbmEubWFjaWVsQHNvbHV0aS5jb20uYnKg
OAYFYEwBAwGgLxMtMDEwMTE5OTk0ODA5MDc3NzA1ODAwMDAwMDAwMDAwMDAwMDAw
MDAwMDAwMDAwoBcGBWBMAQMGoA4TDDAwMDAwMDAwMDAwMKAeBgVgTAEDBaAVExMw
MDAwMDAwMDAwMDAwMDAwMDAwMA0GCSqGSIb3DQEBCwUAA4ICAQBkjBPht/hf+uIZ
H3tDCEuF3DszoXkcYhqw87KLzWAyrYOoXlAwuHsFijMFmtAvQhf8XIXuE2y5VJtH
kee6GsXPtD2tP4q0dT78uZ744JGAzH8PnQkCecnx1NYaHCTDSve5K+yUPuwjb+Z5
KrN4PPFRcSG5B+rhTgxuRW9VBXdioUtqEOOGYZQE5AU8HvpaOfun/ai9xwja0nvp
Z/JDkXKG++nIFmkfGNsLnV7b2Exw6i+D8G2lP4NJhrKikvsQTTVcnvUEjGRMNFvd
h3Qu83MDfPr0jnQft52xdPxUAqtZ4JLniJ0f16bwQAKFlMBPIr6ddWXT07dRAErO
5yD4j3w78RTp2KNjqj2z5j8PegE30CHtow5pZDMTASX6X6+26eM9SUzwPhS/tOeG
pZZDiKaa3Z5yjCfHhz5bLcjnD+A0Jus3VNF+fXSOy2QSg9e4Pn81gUGhQ8kJIZIb
OMzoX13HZbCD+RkqfJOqARSCeBWzolAv23Ggrrm6i8wjRI22CJB00tA1EUcOdi7b
MXN+RzTZaOoRFzuDAGm23s3EthH00P2hlSIhBjfnj2qnPhpttvu2e2+nsvPhQiVB
cFoCiORE2/pWJlDVQct6R+kDkQAETEQm9/WJK9fZOjcElxvUj62Y187tuSE0UVeW
4ez/1QUDSJ4YIl8NRv5xeNXxuZSV/w==
-----END CERTIFICATE-----`

	block, _ := pem.Decode([]byte(pemCertificate))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	var (
		certs []*x509.Certificate
	)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	certs = append(certs, cert)

	signer := TestSigner{
		certificate:     cert,
		signatureDigest: []byte(rawSignature),
	}

	//**
	sd, err := NewSignedData([]byte(rawSignature))
	if err != nil {
		panic(err)
	}
	if err = sd.Sign([]*x509.Certificate{cert}, signer); err != nil {
		panic(err)
	}

	sd.Detached()

	if err = sd.AddTimestamps("https://kvpn.kryptus.com:34443/timestamp"); err != nil {
		panic(err)
	}

	der, err := sd.ToDER()
	if err != nil {
		panic(err)
	}

	//**
	// der, err := SignHash([]byte(rawSignature), certs, signer)
	// fmt.Println(der)

	// f, err := os.Create("data3.der")
	// if err != nil {
	// 	panic(err)
	// }
	// defer f.Close()
	// _, err = f.Write(der)
	// if err != nil {
	// 	panic(err)
	// }

	fmt.Println("done")

	fmt.Println(der)
	// strx := string(der[:])
	// fmt.Println(strx)

	// sign, err := SignHash([]byte(rawSignature), certs, ts)
	// fmt.Println(sign)
}
