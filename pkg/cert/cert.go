package cert

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CertChain struct {
	Certificates []*x509.Certificate
	KeyType      string // "RSA" 或 "ECC"
}

type CertInfo struct {
	Subject          string    `json:"subject"`
	Issuer           string    `json:"issuer"`
	NotBefore        time.Time `json:"notBefore"`
	NotAfter         time.Time `json:"notAfter"`
	SerialNumber     string    `json:"serialNumber"`
	KeyType          string    `json:"keyType"`
	KeyBits          int       `json:"keyBits"`
	RemainingDays    int       `json:"remainingDays"`
	IsCA             bool      `json:"isCA"`
	CommonName       string    `json:"commonName"`
	SubjectAltNames  []string  `json:"subjectAltNames"`
}

type CertificateInfo struct {
	Subject          string    `json:"subject"`
	Issuer           string    `json:"issuer"`
	NotBefore        time.Time `json:"notBefore"`
	NotAfter         time.Time `json:"notAfter"`
	SerialNumber     string    `json:"serialNumber"`
	KeyType          string    `json:"keyType"`
	RemainingDays    int       `json:"remainingDays"`
	CommonName       string    `json:"commonName"`
	SubjectAltNames  []string  `json:"subjectAltNames"`
}

type DownloadResult struct {
	Domain       string
	RSAChain     *CertChain
	ECCChain     *CertChain
	SupportsBoth bool
	Error        error
}

// GetCertificateChainWithOptions 从指定的域名、IP和端口获取证书链
func GetCertificateChainWithOptions(domain string, ip string, port string) (*CertChain, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain, // 设置 SNI
	}

	// 构建连接地址
	address := domain
	if ip != "" {
		address = ip
	}
	if port == "" {
		port = "443"
	}
	address = fmt.Sprintf("%s:%s", address, port)

	conn, err := tls.Dial("tcp", address, conf)
	if err != nil {
		return nil, fmt.Errorf("连接到服务器失败: %v", err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	return &CertChain{Certificates: certs}, nil
}

func GetCertificateChain(domain string) (*CertChain, error) {
	return GetCertificateChainWithOptions(domain, "", "")
}

func LoadCertificateChain(filepath string) (*CertChain, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("读取证书文件失败: %v", err)
	}

	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析证书失败: %v", err)
		}
		certs = append(certs, cert)
		data = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("未找到有效的证书")
	}

	return &CertChain{Certificates: certs}, nil
}

func LoadCertificatesFromDirectory(dirpath string) (*CertChain, error) {
	var certs []*x509.Certificate

	err := filepath.Walk(dirpath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".pem") &&
			!strings.HasSuffix(strings.ToLower(info.Name()), ".crt") {
			return nil
		}

		chain, err := LoadCertificateChain(path)
		if err != nil {
			return fmt.Errorf("加载证书文件 %s 失败: %v", path, err)
		}
		certs = append(certs, chain.Certificates...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("遍历目录失败: %v", err)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("目录中未找到有效的证书")
	}

	return &CertChain{Certificates: certs}, nil
}

func GetCertInfo(cert *x509.Certificate) CertInfo {
	now := time.Now()
	remainingDays := int(cert.NotAfter.Sub(now).Hours() / 24)

	var keyType string
	var keyBits int

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		keyType = "RSA"
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			keyBits = rsaKey.Size() * 8
		}
	case x509.ECDSA:
		keyType = "ECDSA"
		if ecKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			keyBits = ecKey.Params().BitSize
		}
	case x509.Ed25519:
		keyType = "Ed25519"
		keyBits = 256 // Ed25519 always uses 256-bit keys
	default:
		keyType = "Unknown"
		keyBits = 0
	}

	// 获取所有 SAN
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, email := range cert.EmailAddresses {
		sans = append(sans, email)
	}
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}

	return CertInfo{
		Subject:         cert.Subject.String(),
		Issuer:         cert.Issuer.String(),
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		SerialNumber:   cert.SerialNumber.Text(16),
		KeyType:        keyType,
		KeyBits:        keyBits,
		RemainingDays:  remainingDays,
		IsCA:           cert.IsCA,
		CommonName:     cert.Subject.CommonName,
		SubjectAltNames: sans,
	}
}

func CompleteChain(chain *CertChain, rootCAs *x509.CertPool) (*CertChain, error) {
	if len(chain.Certificates) == 0 {
		return nil, fmt.Errorf("证书链为空")
	}

	// 如果证书链已经完整，直接返回
	if isChainComplete(chain.Certificates) {
		return chain, nil
	}

	// 创建一个新的证书链，从叶子证书开始
	var completedCerts []*x509.Certificate
	completedCerts = append(completedCerts, chain.Certificates...)

	// 从最后一个证书开始，尝试获取其上级证书
	lastCert := completedCerts[len(completedCerts)-1]
	maxAttempts := 5 // 最多尝试补全5层证书

	for attempts := 0; attempts < maxAttempts; attempts++ {
		// 如果已经是根证书或可信的中间证书，停止补全
		if lastCert.IsCA && lastCert.Issuer.String() == lastCert.Subject.String() {
			break
		}

		// 检查是否已经在系统根证书中
		if rootCAs != nil {
			roots := x509.NewCertPool()
			roots.AddCert(lastCert)
			if _, err := lastCert.Verify(x509.VerifyOptions{Roots: rootCAs}); err == nil {
				break
			}
		}

		// 获取上级证书的URL
		var issuerURL string
		for _, aia := range lastCert.IssuingCertificateURL {
			issuerURL = aia
			break
		}

		if issuerURL == "" {
			break // 没有上级证书的URL信息
		}

		// 下载上级证书
		issuerCert, err := downloadCertificate(issuerURL)
		if err != nil {
			break
		}

		// 验证签名
		if err := lastCert.CheckSignatureFrom(issuerCert); err != nil {
			break
		}

		// 添加到证书链中
		completedCerts = append(completedCerts, issuerCert)
		lastCert = issuerCert
	}

	return &CertChain{
		Certificates: completedCerts,
		KeyType:     chain.KeyType,
	}, nil
}

func downloadCertificate(url string) (*x509.Certificate, error) {
	// 创建HTTP客户端
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// 发送GET请求
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("下载证书失败: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应内容
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取证书数据失败: %v", err)
	}

	// 尝试解析为DER格式
	cert, err := x509.ParseCertificate(body)
	if err != nil {
		// 如果不是DER格式，尝试解析PEM格式
		block, _ := pem.Decode(body)
		if block == nil {
			return nil, fmt.Errorf("无效的证书格式")
		}
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析证书失败: %v", err)
		}
	}

	return cert, nil
}

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

	// 最后一个证书应该是根证书或可信的中间证书
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