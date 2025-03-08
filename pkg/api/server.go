package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/compose-ssl-chain/pkg/analyzer"
	"github.com/gin-contrib/cors"
)

// CustomFileSystem 包装http.FileSystem以提供自定义的MIME类型
type CustomFileSystem struct {
	fs http.FileSystem
}

func (c *CustomFileSystem) Open(name string) (http.File, error) {
	return c.fs.Open(name)
}

func NewCustomFileSystem(fs http.FileSystem) *CustomFileSystem {
	return &CustomFileSystem{fs: fs}
}

type Server struct {
	analyzer *analyzer.CertAnalyzer
	router   *gin.Engine
}

func NewServer() *Server {
	s := &Server{
		analyzer: analyzer.NewCertAnalyzer(),
		router:   gin.Default(),
	}
	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	// 添加 CORS 中间件
	s.router.Use(cors.Default())

	// API 路由
	s.router.POST("/api/analyze/domain", s.analyzeDomain)
	s.router.POST("/api/analyze/file", s.analyzeFile)
	s.router.POST("/api/export", s.exportCertificates)
	s.router.POST("/api/export/file", s.exportFileAnalysis)

	// 静态文件服务的基础路径
	var staticPath string
	if _, err := os.Stat("/usr/share/ssl-chain-analyzer/assets/web"); err == nil {
		staticPath = "/usr/share/ssl-chain-analyzer/assets/web"
	} else {
		staticPath = "./assets/web"
	}

	// 静态文件服务
	s.router.GET("/assets/*filepath", func(c *gin.Context) {
		path := c.Param("filepath")
		filePath := filepath.Join(staticPath, "assets", path)
		
		if strings.HasSuffix(path, ".js") {
			c.Header("Content-Type", "application/javascript; charset=utf-8")
		} else if strings.HasSuffix(path, ".css") {
			c.Header("Content-Type", "text/css; charset=utf-8")
		}
		c.File(filePath)
	})

	// 主页和其他路由
	s.router.GET("/", func(c *gin.Context) {
		c.File(filepath.Join(staticPath, "index.html"))
	})
	s.router.NoRoute(func(c *gin.Context) {
		c.File(filepath.Join(staticPath, "index.html"))
	})
}

func (s *Server) Run(addr string) error {
	return s.router.Run(addr)
}

type AnalyzeDomainRequest struct {
	Domain string `json:"domain"`
	IP     string `json:"ip,omitempty"`
	Port   string `json:"port,omitempty"`
}

type AnalyzeResponse struct {
	Success bool                    `json:"success"`
	Error   string                 `json:"error,omitempty"`
	Result  *analyzer.AnalyzeResult `json:"result,omitempty"`
}

func (s *Server) analyzeDomain(c *gin.Context) {
	var req AnalyzeDomainRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, AnalyzeResponse{
			Success: false,
			Error:   "Invalid request format",
		})
		return
	}

	result, err := s.analyzer.AnalyzeDomainWithOptions(req.Domain, req.IP, req.Port)
	if err != nil {
		c.JSON(http.StatusInternalServerError, AnalyzeResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, AnalyzeResponse{
		Success: true,
		Result:  result,
	})
}

func (s *Server) analyzeFile(c *gin.Context) {
	file, err := c.FormFile("certificate")
	if err != nil {
		c.JSON(http.StatusBadRequest, AnalyzeResponse{
			Success: false,
			Error:   "No file uploaded",
		})
		return
	}

	// 创建临时文件
	tempFile, err := os.CreateTemp("", "cert-*.pem")
	if err != nil {
		c.JSON(http.StatusInternalServerError, AnalyzeResponse{
			Success: false,
			Error:   "Failed to create temporary file",
		})
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// 保存上传的文件
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, AnalyzeResponse{
			Success: false,
			Error:   "Failed to open uploaded file",
		})
		return
	}
	defer src.Close()

	_, err = io.Copy(tempFile, src)
	if err != nil {
		c.JSON(http.StatusInternalServerError, AnalyzeResponse{
			Success: false,
			Error:   "Failed to save uploaded file",
		})
		return
	}

	// 分析证书
	result, err := s.analyzer.AnalyzeFile(tempFile.Name())
	if err != nil {
		c.JSON(http.StatusInternalServerError, AnalyzeResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, AnalyzeResponse{
		Success: true,
		Result:  result,
	})
}

type ExportRequest struct {
	Domain string `json:"domain"`
	IP     string `json:"ip,omitempty"`
	Port   string `json:"port,omitempty"`
}

func (s *Server) exportCertificates(c *gin.Context) {
	var req ExportRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request format",
		})
		return
	}

	// 导出证书
	exportPath := filepath.Join("certificates", req.Domain)
	var err error
	if req.IP != "" && req.Port != "" {
		err = s.analyzer.ExportCertificatesWithOptions(req.Domain, req.IP, req.Port, exportPath)
	} else {
		err = s.analyzer.ExportCertificates(req.Domain, exportPath)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// 创建 ZIP 文件
	zipPath := fmt.Sprintf("%s.zip", exportPath)
	err = createZip(exportPath, zipPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to create ZIP file",
		})
		return
	}

	// 返回 ZIP 文件
	c.FileAttachment(zipPath, fmt.Sprintf("%s-certificates.zip", req.Domain))
}

func (s *Server) exportFileAnalysis(c *gin.Context) {
	file, err := c.FormFile("certificate")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "No file uploaded",
		})
		return
	}

	// 创建临时文件
	tempFile, err := os.CreateTemp("", "cert-*.pem")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to create temporary file",
		})
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// 保存上传的文件
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to open uploaded file",
		})
		return
	}
	defer src.Close()

	_, err = io.Copy(tempFile, src)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to save uploaded file",
		})
		return
	}

	// 导出证书
	exportPath := filepath.Join("certificates", filepath.Base(file.Filename))
	err = s.analyzer.ExportCertificates(tempFile.Name(), exportPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// 创建 ZIP 文件
	zipPath := fmt.Sprintf("%s.zip", exportPath)
	err = createZip(exportPath, zipPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to create ZIP file",
		})
		return
	}

	// 返回 ZIP 文件
	c.FileAttachment(zipPath, fmt.Sprintf("%s-certificates.zip", filepath.Base(file.Filename)))
} 