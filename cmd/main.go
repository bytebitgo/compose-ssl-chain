package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"path/filepath"

	"github.com/compose-ssl-chain/pkg/analyzer"
	"github.com/compose-ssl-chain/pkg/cert"
	"github.com/compose-ssl-chain/pkg/utils"
	"crypto/x509"
	"encoding/pem"
)

var (
	domain    = flag.String("domain", "", "要分析的域名")
	port      = flag.Int("port", 443, "HTTPS端口")
	outputDir = flag.String("output", "certificates", "证书输出目录")
	export    = flag.Bool("export", false, "是否导出证书")
	verbose   = flag.Bool("verbose", false, "是否显示详细信息")
	certFile  = flag.String("cert", "", "本地证书文件路径")
	certDir   = flag.String("cert-dir", "", "本地证书目录路径")
)

func main() {
	flag.Parse()

	// 获取系统根证书
	rootCAs := analyzer.GetSystemRootCAs()

	// 处理本地证书文件
	if *certFile != "" {
		fmt.Printf("正在分析本地证书文件: %s\n", *certFile)
		chain, err := cert.LoadCertificateChainFromFile(*certFile)
		if err != nil {
			fmt.Printf("加载证书文件失败: %v\n", err)
			os.Exit(1)
		}
		
		// 分析证书链
		analysisResult := analyzer.AnalyzeChain(chain, rootCAs)
		if *verbose {
			fmt.Println(utils.FormatAnalysisResult(analysisResult, chain.KeyType))
		} else {
			printSummary(analysisResult, chain.KeyType)
		}

		// 导出证书
		if *export {
			outputPath := filepath.Join(*outputDir, "chain.pem")
			if err := exportCertificates(chain, outputPath); err != nil {
				fmt.Printf("导出证书失败: %v\n", err)
			}
		}
		
		return
	}

	// 处理本地证书目录
	if *certDir != "" {
		fmt.Printf("正在分析本地证书目录: %s\n", *certDir)
		chain, err := cert.LoadCertificateChainFromDirectory(*certDir)
		if err != nil {
			fmt.Printf("加载证书目录失败: %v\n", err)
			os.Exit(1)
		}
		
		// 分析证书链
		analysisResult := analyzer.AnalyzeChain(chain, rootCAs)
		if *verbose {
			fmt.Println(utils.FormatAnalysisResult(analysisResult, chain.KeyType))
		} else {
			printSummary(analysisResult, chain.KeyType)
		}

		// 导出证书
		if *export {
			outputPath := filepath.Join(*outputDir, "chain.pem")
			if err := exportCertificates(chain, outputPath); err != nil {
				fmt.Printf("导出证书失败: %v\n", err)
			}
		}
		
		return
	}

	// 处理在线域名
	if *domain == "" {
		fmt.Println("请指定域名（-domain）或本地证书文件（-cert）或证书目录（-cert-dir）")
		flag.Usage()
		os.Exit(1)
	}

	// 清理域名（移除协议前缀和路径）
	cleanDomain := *domain
	if strings.HasPrefix(cleanDomain, "http://") {
		cleanDomain = cleanDomain[7:]
	} else if strings.HasPrefix(cleanDomain, "https://") {
		cleanDomain = cleanDomain[8:]
	}
	
	// 移除路径
	if idx := strings.Index(cleanDomain, "/"); idx != -1 {
		cleanDomain = cleanDomain[:idx]
	}

	fmt.Printf("正在分析域名: %s (端口: %d)\n", cleanDomain, *port)

	// 下载证书链
	result, err := cert.DownloadCertificateChain(cleanDomain, *port)
	if err != nil {
		fmt.Printf("下载证书链失败: %v\n", err)
		os.Exit(1)
	}

	// 打印下载结果
	fmt.Println(utils.FormatDownloadResult(result))

	// 分析RSA证书链
	if result.RSAChain != nil {
		rsaAnalysis := analyzer.AnalyzeChain(result.RSAChain, rootCAs)
		if *verbose {
			fmt.Println(utils.FormatAnalysisResult(rsaAnalysis, "RSA"))
		} else {
			printSummary(rsaAnalysis, "RSA")
		}
	}

	// 分析ECC证书链
	if result.ECCChain != nil {
		eccAnalysis := analyzer.AnalyzeChain(result.ECCChain, rootCAs)
		if *verbose {
			fmt.Println(utils.FormatAnalysisResult(eccAnalysis, "ECC"))
		} else {
			printSummary(eccAnalysis, "ECC")
		}
	}

	// 导出证书
	if *export {
		exportCertificateChains(result.RSAChain, result.ECCChain, *outputDir)
	}
}

// printSummary 打印分析结果摘要
func printSummary(result *analyzer.ChainAnalysisResult, chainType string) {
	fmt.Printf("\n=== %s证书链摘要 ===\n", chainType)
	fmt.Printf("证书链完整性: %s\n", utils.FormatBool(result.IsComplete))
	fmt.Printf("证书链可信性: %s\n", utils.FormatBool(result.IsTrusted))
	
	if len(result.Issues) > 0 {
		fmt.Printf("发现 %d 个问题\n", len(result.Issues))
		for _, issue := range result.Issues {
			fmt.Printf("- %s\n", issue)
		}
	} else {
		fmt.Println("未发现问题")
	}
	
	fmt.Printf("证书链长度: %d\n", len(result.CertInfos))
	if len(result.CertInfos) > 0 {
		leaf := result.CertInfos[0]
		fmt.Printf("叶子证书: %s (%s %d位)\n", 
			leaf.Subject, 
			leaf.KeyType, 
			leaf.KeyBits)
	}
}

// exportCertificates 导出证书
func exportCertificates(chain *cert.CertChain, outputPath string) error {
	// 记录原始证书信息
	fmt.Println("\n=== 原始证书信息 ===")
	fmt.Println("原始证书文件包含:")
	for i, cert := range chain.Certificates {
		if i == 0 {
			fmt.Printf("- 叶子证书: %s\n", cert.Subject.CommonName)
		} else {
			fmt.Printf("- %s证书: %s\n", getCertType(cert), cert.Subject.CommonName)
		}
	}

	// 尝试补全证书链
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		fmt.Printf("警告: 无法加载系统根证书: %v\n", err)
	}

	completedChain, err := cert.CompleteChain(chain, rootCAs)
	if err != nil {
		fmt.Printf("警告: 补全证书链失败: %v\n", err)
		completedChain = chain // 如果补全失败，使用原始链
	}

	// 输出补全信息
	if len(completedChain.Certificates) > len(chain.Certificates) {
		fmt.Println("\n=== 证书链补全信息 ===")
		fmt.Println("工具成功补全了证书链:")
		for i := len(chain.Certificates); i < len(completedChain.Certificates); i++ {
			cert := completedChain.Certificates[i]
			fmt.Printf("- 自动下载并添加了%s证书: %s\n", getCertType(cert), cert.Subject.CommonName)
		}
	}

	// 获取证书域名作为子目录名
	var domainName string
	if len(completedChain.Certificates) > 0 {
		// 从叶子证书的 CN 或 SAN 中获取域名
		leaf := completedChain.Certificates[0]
		if len(leaf.DNSNames) > 0 {
			domainName = leaf.DNSNames[0] // 使用第一个 SAN
		} else {
			// 从 CN 中提取域名
			cn := leaf.Subject.CommonName
			if strings.HasPrefix(cn, "*.") {
				cn = cn[2:] // 移除通配符
			}
			domainName = cn
		}
	}
	if domainName == "" {
		domainName = "unknown" // 如果无法获取域名，使用 unknown
	}

	// 准备文件路径
	dir := filepath.Join(filepath.Dir(outputPath), domainName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	base := strings.TrimSuffix(filepath.Base(outputPath), filepath.Ext(outputPath))
	certFile := filepath.Join(dir, base+".crt")
	chainFile := filepath.Join(dir, base+".chain.pem")
	fullchainFile := filepath.Join(dir, base+".fullchain.pem")
	rootcaFile := filepath.Join(dir, base+".rootca.pem")

	// 导出叶子证书
	if err := exportCertificateFile(certFile, completedChain.Certificates[0]); err != nil {
		return fmt.Errorf("导出叶子证书失败: %v", err)
	}

	// 导出中间证书链（不包括叶子证书和根证书）
	if len(completedChain.Certificates) > 2 {
		intermediates := completedChain.Certificates[1 : len(completedChain.Certificates)-1]
		if err := exportCertificatesFile(chainFile, intermediates); err != nil {
			return fmt.Errorf("导出中间证书链失败: %v", err)
		}
	}

	// 导出完整证书链（不包括根证书）
	if len(completedChain.Certificates) > 1 {
		fullchain := completedChain.Certificates[:len(completedChain.Certificates)-1]
		if err := exportCertificatesFile(fullchainFile, fullchain); err != nil {
			return fmt.Errorf("导出完整证书链失败: %v", err)
		}
	}

	// 导出根证书
	if len(completedChain.Certificates) > 0 {
		root := completedChain.Certificates[len(completedChain.Certificates)-1]
		if err := exportCertificateFile(rootcaFile, root); err != nil {
			return fmt.Errorf("导出根证书失败: %v", err)
		}
	}

	// 输出导出信息
	fmt.Println("\n=== 证书导出信息 ===")
	fmt.Printf("证书链已导出到目录: %s\n", dir)
	fmt.Println("导出的文件包含:")
	fmt.Printf("- %s: 叶子证书 (%s)\n", 
		filepath.Base(certFile), 
		completedChain.Certificates[0].Subject.CommonName)
	
	if len(completedChain.Certificates) > 2 {
		fmt.Printf("- %s: 中间证书链 (%d 个证书)\n", 
			filepath.Base(chainFile), 
			len(completedChain.Certificates)-2)
	}
	
	if len(completedChain.Certificates) > 1 {
		fmt.Printf("- %s: 完整证书链 (叶子证书 + 中间证书)\n", 
			filepath.Base(fullchainFile))
	}
	
	fmt.Printf("- %s: 根证书 (%s)\n", 
		filepath.Base(rootcaFile), 
		completedChain.Certificates[len(completedChain.Certificates)-1].Subject.CommonName)

	if len(completedChain.Certificates) > len(chain.Certificates) {
		fmt.Printf("\n总计补全了 %d 个缺失的证书\n", len(completedChain.Certificates)-len(chain.Certificates))
	}

	return nil
}

// getCertType 获取证书类型
func getCertType(cert *x509.Certificate) string {
	if cert.IsCA {
		if cert.Subject.String() == cert.Issuer.String() {
			return "根"
		}
		return "中间"
	}
	return "叶子"
}

// exportCertificateFile 导出单个证书到文件
func exportCertificateFile(filename string, cert *x509.Certificate) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.Encode(file, block)
}

// exportCertificatesFile 导出多个证书到文件
func exportCertificatesFile(filename string, certs []*x509.Certificate) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	for _, cert := range certs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		if err := pem.Encode(file, block); err != nil {
			return fmt.Errorf("写入证书失败: %v", err)
		}
	}
	return nil
}

// exportCertificateChains 导出RSA和ECC证书链
func exportCertificateChains(rsaChain *cert.CertChain, eccChain *cert.CertChain, outputDir string) {
	fmt.Printf("\n正在导出证书到 %s 目录...\n", outputDir)
	
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("创建输出目录失败: %v\n", err)
		return
	}

	if rsaChain != nil {
		rsaPath := filepath.Join(outputDir, "rsa")
		if err := exportCertificates(rsaChain, rsaPath); err != nil {
			fmt.Printf("导出RSA证书链失败: %v\n", err)
		}
	}
	
	if eccChain != nil {
		eccPath := filepath.Join(outputDir, "ecc")
		if err := exportCertificates(eccChain, eccPath); err != nil {
			fmt.Printf("导出ECC证书链失败: %v\n", err)
		}
	}
} 