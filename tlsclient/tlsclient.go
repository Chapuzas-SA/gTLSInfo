package tlsclient

import (
	"fmt"
	"gTLSInfo/common"
	"net"
	"net/http"
	"strconv"
	"time"

	utls "github.com/refraction-networking/utls"
)

func SendRequestAndGetHeaders(host string, port uint16) (http.Header, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("https://%s:%d", host, port)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")
	if resp, err := client.Do(req); err == nil {
		defer resp.Body.Close()
		return resp.Header, nil
	} else {
		return nil, err
	}
}

func UTLSConnection(cfg common.TLSClientConfig) (*utls.ConnectionState, error) {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port)))
	rawConn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()

	uConn := utls.UClient(rawConn, &utls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: true,
		NextProtos:         common.AllALPNProtocols,
	}, utls.HelloCustom)

	spec := &utls.ClientHelloSpec{
		TLSVersMin:   cfg.TLSVersion,
		TLSVersMax:   cfg.TLSVersion,
		CipherSuites: []uint16{cfg.CipherSuite},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: cfg.Host},
			&utls.SupportedVersionsExtension{
				Versions: []uint16{cfg.TLSVersion},
			},
			&utls.KeyShareExtension{
				KeyShares: []utls.KeyShare{
					{Group: utls.X25519},
				},
			},
			&utls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []utls.SignatureScheme{
					utls.PSSWithSHA256,
					utls.ECDSAWithP256AndSHA256,
					utls.PKCS1WithSHA256,
				},
			},
			&utls.SupportedPointsExtension{
				SupportedPoints: []byte{0},
			},
			&utls.SupportedCurvesExtension{
				Curves: []utls.CurveID{
					utls.X25519,
					utls.CurveP256,
				},
			},
		},
	}
	if err := uConn.ApplyPreset(spec); err != nil {
		fmt.Println("Error en ApplyPreset:", err)
		return nil, err
	}

	if err := uConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %T %v", err, err)
	}
	state := uConn.ConnectionState()
	return &state, nil
}

func ProcessTLSInfo(host string, port uint16) common.TLSResult {
	var supported = make(map[string][]common.CipherInfo)
	result := common.TLSResult{Host: host, Port: port, ALPNProtocol: "", Versions: nil, Certificates: nil}
	for tls_version, tls_name := range common.TlsVersions {
		for _, suite := range common.CipherSuitesByVersion[tls_version] {
			state, err := UTLSConnection(common.TLSClientConfig{
				Host:        host,
				Port:        port,
				TLSVersion:  tls_version,
				CipherSuite: suite.ID,
				Timeout:     5 * time.Second,
			})

			if err == nil {
				supported[tls_name] = append(supported[tls_name], suite)
				if result.ALPNProtocol == "" {
					result.ALPNProtocol = state.NegotiatedProtocol
				}
				if len(result.Certificates) == 0 {
					for _, cert := range state.PeerCertificates {
						c := ConvertCertificate(cert)
						result.Certificates = append(result.Certificates, c)
					}
				}
			} else {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					return result
				}
			}
		}
	}
	result.Versions = supported
	result.Headers, _ = SendRequestAndGetHeaders(host, port)
	return result
}
