package cert

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// CertInfo 存储证书信息
type CertInfo struct {
	Subject      string
	Issuer       string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	KeyType      string
	KeyBits      int
	IsCA         bool
}

// CertChain 表示证书链
type CertChain struct {
	Certificates []*x509.Certificate
	KeyType      string // "RSA" 或 "ECC"
}

// DownloadResult 存储下载结果
type DownloadResult struct {
	Domain      string
	RSAChain    *CertChain
	ECCChain    *CertChain
	SupportsBoth bool
	Error       error
}

// DownloadCertificateChain 下载指定域名的证书链
func DownloadCertificateChain(domain string, port int) (*DownloadResult, error) {
	if !strings.Contains(domain, ":") && port != 0 {
		domain = fmt.Sprintf("%s:%d", domain, port)
	}

	result := &DownloadResult{
		Domain: domain,
	}

	// 尝试下载RSA证书
	rsaConn, err := tls.Dial("tcp", domain, &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
	})

	if err == nil {
		defer rsaConn.Close()
		certs := rsaConn.ConnectionState().PeerCertificates
		if len(certs) > 0 {
			result.RSAChain = &CertChain{
				Certificates: certs,
				KeyType:      "RSA",
			}
		}
	}

	// 尝试下载ECC证书
	eccConn, err := tls.Dial("tcp", domain, &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	})

	if err == nil {
		defer eccConn.Close()
		certs := eccConn.ConnectionState().PeerCertificates
		if len(certs) > 0 {
			result.ECCChain = &CertChain{
				Certificates: certs,
				KeyType:      "ECC",
			}
		}
	}

	// 检查是否同时支持RSA和ECC
	result.SupportsBoth = result.RSAChain != nil && result.ECCChain != nil

	return result, nil
}

// GetCertInfo 从x509证书中提取信息
func GetCertInfo(cert *x509.Certificate) CertInfo {
	info := CertInfo{
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		SerialNumber: fmt.Sprintf("%X", cert.SerialNumber),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		IsCA:         cert.IsCA,
	}

	// 确定密钥类型和大小
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeyType = "RSA"
		info.KeyBits = pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.KeyType = "ECC"
		info.KeyBits = pub.Curve.Params().BitSize
	default:
		info.KeyType = "Unknown"
		info.KeyBits = 0
	}

	return info
} 