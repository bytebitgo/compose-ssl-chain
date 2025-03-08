package analyzer

import (
	"crypto/x509"
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

// AnalyzeResult 存储分析结果
type AnalyzeResult struct {
	IsComplete    bool                    `json:"isComplete"`
	IsTrusted     bool                   `json:"isTrusted"`
	HasExpired    bool                   `json:"hasExpired"`
	HasRevoked    bool                   `json:"hasRevoked"`
	Certificates  []cert.CertificateInfo `json:"certificates"`
}

// CertAnalyzer 证书分析器
type CertAnalyzer struct {
	RootCAs *x509.CertPool
}