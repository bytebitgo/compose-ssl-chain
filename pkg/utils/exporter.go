package utils

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/compose-ssl-chain/pkg/cert"
)

// ExportCertificateChain 将证书链导出为PEM格式文件
func ExportCertificateChain(chain *cert.CertChain, domain string, outputDir string) ([]string, error) {
	if chain == nil || len(chain.Certificates) == 0 {
		return nil, fmt.Errorf("证书链为空")
	}

	// 创建输出目录
	chainDir := filepath.Join(outputDir, domain, strings.ToLower(chain.KeyType))
	err := os.MkdirAll(chainDir, 0755)
	if err != nil {
		return nil, fmt.Errorf("创建输出目录失败: %v", err)
	}

	exportedFiles := make([]string, 0, len(chain.Certificates))

	// 导出每个证书
	for i, cert := range chain.Certificates {
		var filename string
		if i == 0 {
			// 叶子证书
			filename = filepath.Join(chainDir, "cert.pem")
		} else if i == len(chain.Certificates)-1 {
			// 根证书
			filename = filepath.Join(chainDir, "root.pem")
		} else {
			// 中间证书
			filename = filepath.Join(chainDir, fmt.Sprintf("intermediate_%d.pem", i))
		}

		// 将证书编码为PEM格式
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		// 写入文件
		err = os.WriteFile(filename, certPEM, 0644)
		if err != nil {
			return exportedFiles, fmt.Errorf("写入证书文件失败: %v", err)
		}

		exportedFiles = append(exportedFiles, filename)
	}

	// 创建完整的证书链文件
	fullChainFile := filepath.Join(chainDir, "fullchain.pem")
	fullChain, err := os.Create(fullChainFile)
	if err != nil {
		return exportedFiles, fmt.Errorf("创建完整证书链文件失败: %v", err)
	}
	defer fullChain.Close()

	for _, cert := range chain.Certificates {
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		fullChain.Write(certPEM)
	}

	exportedFiles = append(exportedFiles, fullChainFile)
	return exportedFiles, nil
}

// ExportAllCertificates 导出所有证书
func ExportAllCertificates(result *cert.DownloadResult, outputDir string) (map[string][]string, error) {
	exportedFiles := make(map[string][]string)

	if result.RSAChain != nil {
		files, err := ExportCertificateChain(result.RSAChain, result.Domain, outputDir)
		if err != nil {
			return exportedFiles, fmt.Errorf("导出RSA证书链失败: %v", err)
		}
		exportedFiles["RSA"] = files
	}

	if result.ECCChain != nil {
		files, err := ExportCertificateChain(result.ECCChain, result.Domain, outputDir)
		if err != nil {
			return exportedFiles, fmt.Errorf("导出ECC证书链失败: %v", err)
		}
		exportedFiles["ECC"] = files
	}

	return exportedFiles, nil
} 