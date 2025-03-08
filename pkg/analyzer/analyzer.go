package analyzer

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/compose-ssl-chain/pkg/cert"
)

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

		// 暂时移除吊销状态检查，因为需要实现实际的 CRL/OCSP 检查
		result.HasRevocationInfo = false
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

func NewCertAnalyzer() *CertAnalyzer {
	rootCAs, _ := x509.SystemCertPool()
	return &CertAnalyzer{
		RootCAs: rootCAs,
	}
}

func (a *CertAnalyzer) AnalyzeDomainWithOptions(domain string, ip string, port string) (*AnalyzeResult, error) {
	chain, err := cert.GetCertificateChainWithOptions(domain, ip, port)
	if err != nil {
		return nil, fmt.Errorf("获取证书链失败: %v", err)
	}

	// 尝试补全证书链
	completedChain, err := cert.CompleteChain(chain, a.RootCAs)
	if err != nil {
		// 如果补全失败，继续使用原始证书链
		completedChain = chain
	}

	analysisResult := AnalyzeChain(completedChain, a.RootCAs)
	return convertToAnalyzeResult(analysisResult), nil
}

func (a *CertAnalyzer) AnalyzeDomain(domain string) (*AnalyzeResult, error) {
	return a.AnalyzeDomainWithOptions(domain, "", "")
}

func (a *CertAnalyzer) AnalyzeFile(filepath string) (*AnalyzeResult, error) {
	chain, err := cert.LoadCertificateChain(filepath)
	if err != nil {
		return nil, fmt.Errorf("加载证书文件失败: %v", err)
	}

	// 尝试补全证书链
	completedChain, err := cert.CompleteChain(chain, a.RootCAs)
	if err != nil {
		// 如果补全失败，继续使用原始证书链
		completedChain = chain
	}

	analysisResult := AnalyzeChain(completedChain, a.RootCAs)
	return convertToAnalyzeResult(analysisResult), nil
}

func (a *CertAnalyzer) AnalyzeDirectory(dirpath string) (*AnalyzeResult, error) {
	chain, err := cert.LoadCertificatesFromDirectory(dirpath)
	if err != nil {
		return nil, fmt.Errorf("加载证书目录失败: %v", err)
	}

	// 尝试补全证书链
	completedChain, err := cert.CompleteChain(chain, a.RootCAs)
	if err != nil {
		// 如果补全失败，继续使用原始证书链
		completedChain = chain
	}

	analysisResult := AnalyzeChain(completedChain, a.RootCAs)
	return convertToAnalyzeResult(analysisResult), nil
}

func (a *CertAnalyzer) ExportCertificatesWithOptions(domain string, ip string, port string, exportPath string) error {
	chain, err := cert.GetCertificateChainWithOptions(domain, ip, port)
	if err != nil {
		return fmt.Errorf("获取证书链失败: %v", err)
	}

	// 尝试补全证书链
	completedChain, err := cert.CompleteChain(chain, a.RootCAs)
	if err != nil {
		// 如果补全失败，继续使用原始证书链
		completedChain = chain
	}

	// 创建带时间戳的导出目录
	timestamp := time.Now().Format("20060102_150405")
	exportDir := filepath.Join(exportPath, fmt.Sprintf("%s_%s", domain, timestamp))
	if err := os.MkdirAll(exportDir, 0755); err != nil {
		return fmt.Errorf("创建导出目录失败: %v", err)
	}

	// 导出叶子证书
	certPath := filepath.Join(exportDir, "cert.pem")
	if err := exportCertificateFile(certPath, completedChain.Certificates[0]); err != nil {
		return fmt.Errorf("导出叶子证书失败: %v", err)
	}

	// 导出中间证书链
	if len(completedChain.Certificates) > 1 {
		intermediatesPath := filepath.Join(exportDir, "chain.pem")
		intermediates := completedChain.Certificates[1:len(completedChain.Certificates)-1]
		if len(intermediates) > 0 {
			if err := exportCertificatesFile(intermediatesPath, intermediates); err != nil {
				return fmt.Errorf("导出中间证书链失败: %v", err)
			}
		}
	}

	// 导出根证书（CA证书）
	if len(completedChain.Certificates) > 1 {
		caPath := filepath.Join(exportDir, "ca.pem")
		ca := completedChain.Certificates[len(completedChain.Certificates)-1]
		if err := exportCertificateFile(caPath, ca); err != nil {
			return fmt.Errorf("导出CA证书失败: %v", err)
		}
	}

	// 导出完整证书链
	fullchainPath := filepath.Join(exportDir, "fullchain.pem")
	if err := exportCertificatesFile(fullchainPath, completedChain.Certificates); err != nil {
		return fmt.Errorf("导出完整证书链失败: %v", err)
	}

	// 创建说明文件
	readmePath := filepath.Join(exportDir, "README.txt")
	readmeContent := fmt.Sprintf(`证书链导出说明：
域名: %s
IP地址: %s
端口: %s
导出时间: %s

文件说明：
- cert.pem: 叶子证书（服务器证书）
- chain.pem: 中间证书链
- ca.pem: 根证书（CA证书）
- fullchain.pem: 完整证书链（包含所有证书）

证书链长度: %d
`, domain, ip, port, time.Now().Format("2006-01-02 15:04:05"), len(completedChain.Certificates))

	if err := os.WriteFile(readmePath, []byte(readmeContent), 0644); err != nil {
		return fmt.Errorf("创建说明文件失败: %v", err)
	}

	return nil
}

func (a *CertAnalyzer) ExportCertificates(source string, exportPath string) error {
	var chain *cert.CertChain
	var err error

	// 判断source是域名还是文件路径
	if _, err := os.Stat(source); err == nil {
		// source是文件路径
		chain, err = cert.LoadCertificateChain(source)
		if err != nil {
			return fmt.Errorf("加载证书文件失败: %v", err)
		}
	} else {
		// source是域名
		chain, err = cert.GetCertificateChain(source)
		if err != nil {
			return fmt.Errorf("获取证书链失败: %v", err)
		}
	}

	// 尝试补全证书链
	completedChain, err := cert.CompleteChain(chain, a.RootCAs)
	if err != nil {
		// 如果补全失败，继续使用原始证书链
		completedChain = chain
	}

	// 创建带时间戳的导出目录
	timestamp := time.Now().Format("20060102_150405")
	exportDir := filepath.Join(exportPath, fmt.Sprintf("%s_%s", filepath.Base(source), timestamp))
	if err := os.MkdirAll(exportDir, 0755); err != nil {
		return fmt.Errorf("创建导出目录失败: %v", err)
	}

	// 导出叶子证书
	certPath := filepath.Join(exportDir, "cert.pem")
	if err := exportCertificateFile(certPath, completedChain.Certificates[0]); err != nil {
		return fmt.Errorf("导出叶子证书失败: %v", err)
	}

	// 导出中间证书链
	if len(completedChain.Certificates) > 1 {
		intermediatesPath := filepath.Join(exportDir, "chain.pem")
		intermediates := completedChain.Certificates[1:len(completedChain.Certificates)-1]
		if len(intermediates) > 0 {
			if err := exportCertificatesFile(intermediatesPath, intermediates); err != nil {
				return fmt.Errorf("导出中间证书链失败: %v", err)
			}
		}
	}

	// 导出根证书（CA证书）
	if len(completedChain.Certificates) > 1 {
		caPath := filepath.Join(exportDir, "ca.pem")
		ca := completedChain.Certificates[len(completedChain.Certificates)-1]
		if err := exportCertificateFile(caPath, ca); err != nil {
			return fmt.Errorf("导出CA证书失败: %v", err)
		}
	}

	// 导出完整证书链
	fullchainPath := filepath.Join(exportDir, "fullchain.pem")
	if err := exportCertificatesFile(fullchainPath, completedChain.Certificates); err != nil {
		return fmt.Errorf("导出完整证书链失败: %v", err)
	}

	// 创建说明文件
	readmePath := filepath.Join(exportDir, "README.txt")
	readmeContent := fmt.Sprintf(`证书链导出说明：
来源: %s
导出时间: %s

文件说明：
- cert.pem: 叶子证书（服务器证书）
- chain.pem: 中间证书链
- ca.pem: 根证书（CA证书）
- fullchain.pem: 完整证书链（包含所有证书）

证书链长度: %d
`, source, time.Now().Format("2006-01-02 15:04:05"), len(completedChain.Certificates))

	if err := os.WriteFile(readmePath, []byte(readmeContent), 0644); err != nil {
		return fmt.Errorf("创建说明文件失败: %v", err)
	}

	return nil
}

func convertToAnalyzeResult(result *ChainAnalysisResult) *AnalyzeResult {
	certificates := make([]cert.CertificateInfo, len(result.CertInfos))
	for i, certInfo := range result.CertInfos {
		certificates[i] = cert.CertificateInfo{
			Subject:         certInfo.Subject,
			Issuer:         certInfo.Issuer,
			NotBefore:      certInfo.NotBefore,
			NotAfter:       certInfo.NotAfter,
			SerialNumber:   certInfo.SerialNumber,
			KeyType:        certInfo.KeyType,
			RemainingDays:  certInfo.RemainingDays,
			CommonName:     certInfo.CommonName,
			SubjectAltNames: certInfo.SubjectAltNames,
		}
	}

	return &AnalyzeResult{
		IsComplete:   result.IsComplete,
		IsTrusted:    result.IsTrusted,
		HasExpired:   result.HasExpiredCerts,
		HasRevoked:   result.HasRevocationInfo,
		Certificates: certificates,
	}
}

func exportCertificateFile(filepath string, cert *x509.Certificate) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

func exportCertificatesFile(filepath string, certs []*x509.Certificate) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, cert := range certs {
		err := pem.Encode(file, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return err
		}
	}

	return nil
} 