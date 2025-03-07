package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// AIA (Authority Information Access) 信息
type AIAInfo struct {
	IssuerURL      string
	OCSPServer     string
	CRLDistPoint   string
}

// 从证书中提取AIA信息
func getAIAInfo(cert *x509.Certificate) AIAInfo {
	info := AIAInfo{}
	
	// 获取颁发者URL
	for _, url := range cert.IssuingCertificateURL {
		info.IssuerURL = url
		break
	}

	// 获取OCSP服务器
	if len(cert.OCSPServer) > 0 {
		info.OCSPServer = cert.OCSPServer[0]
	}

	// 获取CRL分发点
	if len(cert.CRLDistributionPoints) > 0 {
		info.CRLDistPoint = cert.CRLDistributionPoints[0]
	}

	return info
}

// 从URL下载证书
func downloadCertFromURL(url string) (*x509.Certificate, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("下载证书失败: %v", err)
	}
	defer resp.Body.Close()

	certData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取证书数据失败: %v", err)
	}

	// 尝试解析PEM格式
	block, _ := pem.Decode(certData)
	if block != nil && block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析PEM证书失败: %v", err)
		}
		return cert, nil
	}

	// 尝试解析DER格式
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("解析DER证书失败: %v", err)
	}

	return cert, nil
}

// CompleteChain 尝试补全证书链
func CompleteChain(chain *CertChain, rootCAs *x509.CertPool) (*CertChain, error) {
	if chain == nil || len(chain.Certificates) == 0 {
		return nil, fmt.Errorf("证书链为空")
	}

	// 创建一个新的证书链
	completedChain := &CertChain{
		Certificates: make([]*x509.Certificate, 0),
		KeyType:     chain.KeyType,
	}

	// 添加叶子证书
	completedChain.Certificates = append(completedChain.Certificates, chain.Certificates[0])
	currentCert := chain.Certificates[0]

	// 用于存储已处理的证书序列号，避免循环
	processedSerials := make(map[string]bool)
	processedSerials[currentCert.SerialNumber.String()] = true

	// 尝试构建完整的链
	for {
		// 如果当前证书是自签名的，停止
		if currentCert.IsCA && currentCert.Subject.String() == currentCert.Issuer.String() {
			break
		}

		// 获取AIA信息
		aiaInfo := getAIAInfo(currentCert)

		// 首先在现有的证书链中查找颁发者
		issuerFound := false
		for _, cert := range chain.Certificates[1:] {
			if cert.Subject.String() == currentCert.Issuer.String() {
				if !processedSerials[cert.SerialNumber.String()] {
					completedChain.Certificates = append(completedChain.Certificates, cert)
					currentCert = cert
					processedSerials[cert.SerialNumber.String()] = true
					issuerFound = true
					break
				}
			}
		}

		if issuerFound {
			continue
		}

		// 如果在AIA中有颁发者URL，尝试下载
		if aiaInfo.IssuerURL != "" {
			issuerCert, err := downloadCertFromURL(aiaInfo.IssuerURL)
			if err == nil && !processedSerials[issuerCert.SerialNumber.String()] {
				completedChain.Certificates = append(completedChain.Certificates, issuerCert)
				currentCert = issuerCert
				processedSerials[issuerCert.SerialNumber.String()] = true
				continue
			}
		}

		// 尝试在系统根证书中查找
		if rootCAs != nil {
			subjects := rootCAs.Subjects()
			for _, subject := range subjects {
				if currentCert.Issuer.String() == string(subject) {
					// 找到了根证书，停止搜索
					return completedChain, nil
				}
			}
		}

		// 如果无法找到更多的证书，停止
		break
	}

	return completedChain, nil
}

// ReadCertificateFromFile 从文件中读取证书
func ReadCertificateFromFile(filePath string) (*x509.Certificate, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取证书文件失败: %v", err)
	}

	// 尝试解析PEM格式
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析PEM证书失败: %v", err)
		}
		return cert, nil
	}

	// 尝试解析DER格式
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("解析DER证书失败: %v", err)
	}

	return cert, nil
}

// ReadCertificatesFromDirectory 从目录中读取所有证书
func ReadCertificatesFromDirectory(dirPath string) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".pem" || ext == ".crt" || ext == ".cer" {
			cert, err := ReadCertificateFromFile(path)
			if err != nil {
				fmt.Printf("警告: 无法读取证书 %s: %v\n", path, err)
				return nil
			}
			certificates = append(certificates, cert)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("遍历目录失败: %v", err)
	}

	return certificates, nil
}

// BuildCertificateChain 从证书列表中构建证书链
func BuildCertificateChain(certs []*x509.Certificate) (*CertChain, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("没有提供证书")
	}

	// 找到叶子证书（通常是第一个非CA证书）
	var leafCert *x509.Certificate
	for _, cert := range certs {
		if !cert.IsCA {
			leafCert = cert
			break
		}
	}

	// 如果没有找到非CA证书，使用第一个证书作为叶子证书
	if leafCert == nil {
		leafCert = certs[0]
	}

	// 构建证书链
	chain := []*x509.Certificate{leafCert}
	remainingCerts := make([]*x509.Certificate, 0)
	for _, cert := range certs {
		if cert.SerialNumber.Cmp(leafCert.SerialNumber) != 0 {
			remainingCerts = append(remainingCerts, cert)
		}
	}

	// 尝试构建完整的链
	current := leafCert
	for len(remainingCerts) > 0 {
		found := false
		for i, cert := range remainingCerts {
			// 检查当前证书是否由此证书签发
			if current.Issuer.String() == cert.Subject.String() {
				chain = append(chain, cert)
				current = cert
				// 从剩余证书中移除此证书
				remainingCerts = append(remainingCerts[:i], remainingCerts[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			break
		}
	}

	// 确定证书类型
	keyType := "Unknown"
	if leafCert != nil {
		info := GetCertInfo(leafCert)
		keyType = info.KeyType
	}

	return &CertChain{
		Certificates: chain,
		KeyType:      keyType,
	}, nil
}

// LoadCertificateChainFromFile 从单个文件加载证书链
func LoadCertificateChainFromFile(filePath string) (*CertChain, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取证书文件失败: %v", err)
	}

	var certs []*x509.Certificate

	// 尝试解析PEM格式的证书链
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("解析PEM证书失败: %v", err)
			}
			certs = append(certs, cert)
		}
		data = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("文件中没有找到有效的证书")
	}

	return BuildCertificateChain(certs)
}

// LoadCertificateChainFromDirectory 从目录加载证书链
func LoadCertificateChainFromDirectory(dirPath string) (*CertChain, error) {
	certs, err := ReadCertificatesFromDirectory(dirPath)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("目录中没有找到有效的证书")
	}

	return BuildCertificateChain(certs)
} 