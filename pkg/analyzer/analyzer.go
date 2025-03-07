package analyzer

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/compose-ssl-chain/pkg/cert"
)

// ChainAnalysisResult 存储证书链分析结果
type ChainAnalysisResult struct {
	IsComplete       bool
	IsTrusted        bool
	HasExpiredCerts  bool
	HasRevocationInfo bool
	Issues           []string
	CertInfos        []cert.CertInfo
}

// AnalyzeChain 分析证书链的完整性和可信性
func AnalyzeChain(chain *cert.CertChain, rootCAs *x509.CertPool) *ChainAnalysisResult {
	if chain == nil || len(chain.Certificates) == 0 {
		return &ChainAnalysisResult{
			IsComplete: false,
			IsTrusted:  false,
			Issues:     []string{"证书链为空"},
		}
	}

	result := &ChainAnalysisResult{
		IsComplete:      true,
		IsTrusted:       false,
		HasExpiredCerts: false,
		Issues:          []string{},
		CertInfos:       make([]cert.CertInfo, 0, len(chain.Certificates)),
	}

	// 提取每个证书的信息
	for _, certificate := range chain.Certificates {
		certInfo := cert.GetCertInfo(certificate)
		result.CertInfos = append(result.CertInfos, certInfo)

		// 检查证书是否过期
		now := time.Now()
		if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
			result.HasExpiredCerts = true
			result.Issues = append(result.Issues, 
				fmt.Sprintf("证书 %s 已过期或尚未生效 (有效期: %s 至 %s)", 
					certificate.Subject.CommonName,
					certificate.NotBefore.Format("2006-01-02"),
					certificate.NotAfter.Format("2006-01-02")))
		}

		// 检查是否有吊销信息
		if len(certificate.CRLDistributionPoints) > 0 || len(certificate.OCSPServer) > 0 {
			result.HasRevocationInfo = true
		}
	}

	// 验证证书链的完整性
	if !isChainComplete(chain.Certificates) {
		result.IsComplete = false
		result.Issues = append(result.Issues, "证书链不完整，缺少中间证书")
	}

	// 验证证书链的可信性
	if rootCAs != nil {
		leaf := chain.Certificates[0]
		intermediates := x509.NewCertPool()
		for i := 1; i < len(chain.Certificates); i++ {
			intermediates.AddCert(chain.Certificates[i])
		}

		opts := x509.VerifyOptions{
			Roots:         rootCAs,
			Intermediates: intermediates,
		}

		_, err := leaf.Verify(opts)
		if err == nil {
			result.IsTrusted = true
		} else {
			result.Issues = append(result.Issues, fmt.Sprintf("证书链不可信: %v", err))
		}
	} else {
		result.Issues = append(result.Issues, "未提供根证书池，无法验证可信性")
	}

	return result
}

// isChainComplete 检查证书链是否完整
func isChainComplete(certs []*x509.Certificate) bool {
	if len(certs) <= 1 {
		return false
	}

	// 检查每个证书是否由下一个证书签发
	for i := 0; i < len(certs)-1; i++ {
		cert := certs[i]
		issuer := certs[i+1]

		// 检查发行者和主题是否匹配
		if cert.Issuer.String() != issuer.Subject.String() {
			return false
		}

		// 验证签名
		err := cert.CheckSignatureFrom(issuer)
		if err != nil {
			return false
		}
	}

	// 证书链完整的条件：
	// 1. 最后一个证书是根证书（自签名）
	// 2. 或者最后一个证书是可信的中间证书
	lastCert := certs[len(certs)-1]
	if lastCert.IsCA {
		if lastCert.Issuer.String() == lastCert.Subject.String() {
			// 自签名根证书
			err := lastCert.CheckSignature(lastCert.SignatureAlgorithm, lastCert.RawTBSCertificate, lastCert.Signature)
			return err == nil
		}
		// 可信的中间证书也是可以的
		return true
	}

	return false
}

// GetSystemRootCAs 获取系统根证书
func GetSystemRootCAs() *x509.CertPool {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	return rootCAs
} 