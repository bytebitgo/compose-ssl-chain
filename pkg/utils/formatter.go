package utils

import (
	"fmt"
	"strings"
	"time"

	"github.com/compose-ssl-chain/pkg/analyzer"
	"github.com/compose-ssl-chain/pkg/cert"
)

// FormatCertInfo 格式化证书信息
func FormatCertInfo(info cert.CertInfo) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("主题: %s\n", info.Subject))
	sb.WriteString(fmt.Sprintf("发行者: %s\n", info.Issuer))
	sb.WriteString(fmt.Sprintf("序列号: %s\n", info.SerialNumber))
	sb.WriteString(fmt.Sprintf("有效期: %s 至 %s\n", 
		info.NotBefore.Format("2006-01-02 15:04:05"),
		info.NotAfter.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("密钥类型: %s (%d位)\n", info.KeyType, info.KeyBits))
	sb.WriteString(fmt.Sprintf("是否CA: %t\n", info.IsCA))
	
	// 计算证书剩余有效期
	daysLeft := int(info.NotAfter.Sub(time.Now()).Hours() / 24)
	sb.WriteString(fmt.Sprintf("剩余有效期: %d天\n", daysLeft))

	return sb.String()
}

// FormatAnalysisResult 格式化分析结果
func FormatAnalysisResult(result *analyzer.ChainAnalysisResult, chainType string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("=== %s证书链分析结果 ===\n", chainType))
	sb.WriteString(fmt.Sprintf("证书链完整性: %s\n", formatBool(result.IsComplete)))
	sb.WriteString(fmt.Sprintf("证书链可信性: %s\n", formatBool(result.IsTrusted)))
	sb.WriteString(fmt.Sprintf("包含过期证书: %s\n", formatBool(result.HasExpiredCerts)))
	sb.WriteString(fmt.Sprintf("包含吊销信息: %s\n", formatBool(result.HasRevocationInfo)))
	
	if len(result.Issues) > 0 {
		sb.WriteString("\n问题:\n")
		for _, issue := range result.Issues {
			sb.WriteString(fmt.Sprintf("- %s\n", issue))
		}
	}

	sb.WriteString("\n证书链详情:\n")
	for i, certInfo := range result.CertInfos {
		sb.WriteString(fmt.Sprintf("\n[%d] %s\n", i+1, certInfo.Subject))
		sb.WriteString(strings.Repeat("-", 40) + "\n")
		sb.WriteString(FormatCertInfo(certInfo))
	}

	return sb.String()
}

// FormatDownloadResult 格式化下载结果
func FormatDownloadResult(result *cert.DownloadResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("域名: %s\n", result.Domain))
	sb.WriteString(fmt.Sprintf("支持双证书: %s\n", formatBool(result.SupportsBoth)))
	
	if result.RSAChain != nil {
		sb.WriteString(fmt.Sprintf("\n找到RSA证书链 (%d个证书)\n", len(result.RSAChain.Certificates)))
	} else {
		sb.WriteString("\n未找到RSA证书链\n")
	}
	
	if result.ECCChain != nil {
		sb.WriteString(fmt.Sprintf("\n找到ECC证书链 (%d个证书)\n", len(result.ECCChain.Certificates)))
	} else {
		sb.WriteString("\n未找到ECC证书链\n")
	}

	return sb.String()
}

// FormatBool 格式化布尔值为中文（导出版本）
func FormatBool(b bool) string {
	return formatBool(b)
}

// formatBool 格式化布尔值为中文
func formatBool(b bool) string {
	if b {
		return "是"
	}
	return "否"
} 