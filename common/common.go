package common

import (
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

type TaskOptions struct {
	Concurrency int
}

type Pipeline struct {
	Options     *TaskOptions
	ResultsChan chan string
}

type Normalized struct {
	Host       string
	Port       uint16
	ServerName string
}

type TLSClientConfig struct {
	Host        string
	Port        uint16
	Timeout     time.Duration
	TLSVersion  uint16
	CipherSuite uint16
}

type TLSResult struct {
	Host         string                  `json:"host"`
	Port         uint16                  `json:"port"`
	Versions     map[string][]CipherInfo `json:"tls"`
	Certificates []CertificateJSON       `json:"certs"`
	ALPNProtocol string                  `json:"alpn"`
	Headers      http.Header             `json:"headers"`
}

/** TLSCLIENT Versiones TLS y algoritmos de cifrado **/
// https://github.com/refraction-networking/utls/blob/master/common.go
var TlsVersions = map[uint16]string{
	0x0301: "TLS 1.0",
	0x0302: "TLS 1.1",
	0x0303: "TLS 1.2",
	0x0304: "TLS 1.3",
}

// https://github.com/refraction-networking/utls/blob/master/cipher_suites.go
type CipherInfo struct {
	ID         uint16 `json:"id"`
	Name       string `json:"name"`
	KeyExch    string `json:"key_exchange"`
	Encryption string `json:"encryption"`
	Bits       int    `json:"bits"`
}

// https://github.com/refraction-networking/utls/blob/master/cipher_suites.go
var CipherSuitesByVersion = map[uint16][]CipherInfo{
	utls.VersionTLS10: {
		{ID: 0x0005, Name: "TLS_RSA_WITH_RC4_128_SHA", KeyExch: "RSA", Encryption: "RC4", Bits: 128},
		{ID: 0x000a, Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", KeyExch: "RSA", Encryption: "3DES", Bits: 168},
		{ID: 0x002f, Name: "TLS_RSA_WITH_AES_128_CBC_SHA", KeyExch: "RSA", Encryption: "AES", Bits: 128},
		{ID: 0x0035, Name: "TLS_RSA_WITH_AES_256_CBC_SHA", KeyExch: "RSA", Encryption: "AES", Bits: 256},

		{ID: 0xc007, Name: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", KeyExch: "ECDHE_ECDSA", Encryption: "RC4", Bits: 128},
		{ID: 0xc009, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", KeyExch: "ECDHE_ECDSA", Encryption: "AES", Bits: 128},
		{ID: 0xc00a, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", KeyExch: "ECDHE_ECDSA", Encryption: "AES", Bits: 256},
		{ID: 0xc011, Name: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", KeyExch: "ECDHE_RSA", Encryption: "RC4", Bits: 128},
		{ID: 0xc012, Name: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", KeyExch: "ECDHE_RSA", Encryption: "3DES", Bits: 168},
		{ID: 0xc013, Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", KeyExch: "ECDHE_RSA", Encryption: "AES", Bits: 128},
		{ID: 0xc014, Name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", KeyExch: "ECDHE_RSA", Encryption: "AES", Bits: 256},
	},
	utls.VersionTLS11: {
		{ID: 0x0005, Name: "TLS_RSA_WITH_RC4_128_SHA", KeyExch: "RSA", Encryption: "RC4", Bits: 128},
		{ID: 0x000a, Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", KeyExch: "RSA", Encryption: "3DES", Bits: 168},
		{ID: 0x002f, Name: "TLS_RSA_WITH_AES_128_CBC_SHA", KeyExch: "RSA", Encryption: "AES", Bits: 128},
		{ID: 0x0035, Name: "TLS_RSA_WITH_AES_256_CBC_SHA", KeyExch: "RSA", Encryption: "AES", Bits: 256},

		{ID: 0xc007, Name: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", KeyExch: "ECDHE_ECDSA", Encryption: "RC4", Bits: 128},
		{ID: 0xc009, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", KeyExch: "ECDHE_ECDSA", Encryption: "AES", Bits: 128},
		{ID: 0xc00a, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", KeyExch: "ECDHE_ECDSA", Encryption: "AES", Bits: 256},
		{ID: 0xc011, Name: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", KeyExch: "ECDHE_RSA", Encryption: "RC4", Bits: 128},
		{ID: 0xc012, Name: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", KeyExch: "ECDHE_RSA", Encryption: "3DES", Bits: 168},
		{ID: 0xc013, Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", KeyExch: "ECDHE_RSA", Encryption: "AES", Bits: 128},
		{ID: 0xc014, Name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", KeyExch: "ECDHE_RSA", Encryption: "AES", Bits: 256},
	},
	utls.VersionTLS12: {
		// RC4 (obsoleto)
		{ID: 0x0005, Name: "TLS_RSA_WITH_RC4_128_SHA", KeyExch: "RSA", Encryption: "RC4", Bits: 128},
		{ID: 0xc007, Name: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", KeyExch: "ECDHE_ECDSA", Encryption: "RC4", Bits: 128},
		{ID: 0xc011, Name: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", KeyExch: "ECDHE_RSA", Encryption: "RC4", Bits: 128},
		// 3DES
		{ID: 0x000a, Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", KeyExch: "RSA", Encryption: "3DES", Bits: 168},
		{ID: 0xc012, Name: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", KeyExch: "ECDHE_RSA", Encryption: "3DES", Bits: 168},
		// AES CBC
		{ID: 0x002f, Name: "TLS_RSA_WITH_AES_128_CBC_SHA", KeyExch: "RSA", Encryption: "AES", Bits: 128},
		{ID: 0x0035, Name: "TLS_RSA_WITH_AES_256_CBC_SHA", KeyExch: "RSA", Encryption: "AES", Bits: 256},
		{ID: 0x003c, Name: "TLS_RSA_WITH_AES_128_CBC_SHA256", KeyExch: "RSA", Encryption: "AES", Bits: 128},
		{ID: 0xc009, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", KeyExch: "ECDHE_ECDSA", Encryption: "AES", Bits: 128},
		{ID: 0xc00a, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", KeyExch: "ECDHE_ECDSA", Encryption: "AES", Bits: 256},
		{ID: 0xc013, Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", KeyExch: "ECDHE_RSA", Encryption: "AES", Bits: 128},
		{ID: 0xc014, Name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", KeyExch: "ECDHE_RSA", Encryption: "AES", Bits: 256},
		{ID: 0xc023, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", KeyExch: "ECDHE_ECDSA", Encryption: "AES", Bits: 128},
		{ID: 0xc027, Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", KeyExch: "ECDHE_RSA", Encryption: "AES", Bits: 128},
		// AES GCM
		{ID: 0x009c, Name: "TLS_RSA_WITH_AES_128_GCM_SHA256", KeyExch: "RSA", Encryption: "AESGCM", Bits: 128},
		{ID: 0x009d, Name: "TLS_RSA_WITH_AES_256_GCM_SHA384", KeyExch: "RSA", Encryption: "AESGCM", Bits: 256},
		{ID: 0xc02f, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", KeyExch: "ECDHE_RSA", Encryption: "AESGCM", Bits: 128},
		{ID: 0xc030, Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", KeyExch: "ECDHE_RSA", Encryption: "AESGCM", Bits: 256},
		{ID: 0xc02b, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", KeyExch: "ECDHE_ECDSA", Encryption: "AESGCM", Bits: 128},
		{ID: 0xc02c, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", KeyExch: "ECDHE_ECDSA", Encryption: "AESGCM", Bits: 256},
	},
	utls.VersionTLS13: {
		{ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256", KeyExch: "ECDHE", Encryption: "AESGCM", Bits: 128},
		{ID: 0x1302, Name: "TLS_AES_256_GCM_SHA384", KeyExch: "ECDHE", Encryption: "AESGCM", Bits: 256},
		{ID: 0x1303, Name: "TLS_CHACHA20_POLY1305_SHA256", KeyExch: "ECDHE", Encryption: "CHACHA20_POLY1305", Bits: 256},
		{ID: 0x1304, Name: "TLS_AES_128_CCM_SHA256", KeyExch: "ECDHE", Encryption: "AESCCM", Bits: 128},
		{ID: 0x1305, Name: "TLS_AES_128_CCM_8_SHA256", KeyExch: "ECDHE", Encryption: "AESCCM_8", Bits: 128},
	},
}

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
var AllALPNProtocols = []string{"http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3", "stun.turn", "stun.nat-discovery", "h2", "h2c", "webrtc", "c-webrtc", "ftp", "imap", "pop3", "managesieve", "coap", "co", "xmpp-client", "xmpp-server", "acme-tls/1", "mqtt", "dot", "sunrpc", "h3", "smb", "irc", "nntp", "nnsp", "doq", "sip/2", "tds/8.0", "dicom", "postgresql", "radius/1.0", "radius/1.1"}

/* X509 */
type CertificateJSON struct {
	Signature          string `json:"signature"` // base64
	SignatureAlgorithm string `json:"signature_algorithm"`

	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	PublicKey          string `json:"public_key"` // placeholder

	Version      int       `json:"version"`
	SerialNumber string    `json:"serial_number"` // decimal
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`

	KeyUsage    []string `json:"key_usage"`
	ExtKeyUsage []string `json:"ext_key_usage"`

	IsCA                  bool `json:"is_ca"`
	MaxPathLen            int  `json:"max_path_len"`
	MaxPathLenZero        bool `json:"max_path_len_zero"`
	BasicConstraintsValid bool `json:"basic_constraints_valid"`

	SubjectKeyId   string `json:"subject_key_id"`
	AuthorityKeyId string `json:"authority_key_id"`

	DNSNames       []string `json:"dns_names"`
	EmailAddresses []string `json:"email_addresses"`
	IPAddresses    []string `json:"ip_addresses"`
	URIs           []string `json:"uris"`

	OCSPServer            []string `json:"ocsp_server"`
	IssuingCertificateURL []string `json:"issuing_certificate_url"`

	UnhandledCriticalExtensions []string `json:"unhandled_critical_extensions"`
	PolicyIdentifiers           []string `json:"policy_identifiers"`
}
