package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/compose-ssl-chain/pkg/analyzer"
	"github.com/compose-ssl-chain/pkg/cert"
	"github.com/compose-ssl-chain/pkg/utils"
)

var (
	domain    = flag.String("domain", "", "要分析的域名")
	port      = flag.Int("port", 443, "HTTPS端口")
	outputDir = flag.String("output", "certificates", "证书输出目录")
	export    = flag.Bool("export", false, "是否导出证书")
	verbose   = flag.Bool("verbose", false, "是否显示详细信息")
)

func main() {
	flag.Parse()

	if *domain == "" {
		fmt.Println("请指定域名，例如: -domain example.com")
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

	// 获取系统根证书
	rootCAs := analyzer.GetSystemRootCAs()

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
		fmt.Printf("\n正在导出证书到 %s 目录...\n", *outputDir)
		exportedFiles, err := utils.ExportAllCertificates(result, *outputDir)
		if err != nil {
			fmt.Printf("导出证书失败: %v\n", err)
		} else {
			for keyType, files := range exportedFiles {
				fmt.Printf("已导出 %s 证书链 (%d 个文件)\n", keyType, len(files))
				if *verbose {
					for _, file := range files {
						fmt.Printf("  - %s\n", file)
					}
				}
			}
		}
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