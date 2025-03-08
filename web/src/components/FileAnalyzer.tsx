import { useState } from 'react'
import {
  Box,
  Button,
  Alert,
  CircularProgress,
  Card,
  CardContent,
  Typography,
  Grid,
  Chip,
  IconButton,
} from '@mui/material'
import { CheckCircle, Error, Warning, Upload, Download, Clear, ExpandMore, ExpandLess } from '@mui/icons-material'
import axios from 'axios'

interface CertificateInfo {
  subject: string
  issuer: string
  notBefore: string
  notAfter: string
  serialNumber: string
  keyType: string
  remainingDays: number
  commonName: string
  subjectAltNames: string[]
}

interface AnalysisResult {
  isComplete: boolean
  isTrusted: boolean
  hasExpired: boolean
  hasRevoked: boolean
  certificates: CertificateInfo[]
}

export default function FileAnalyzer() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [exportLoading, setExportLoading] = useState(false)
  const [expandedSans, setExpandedSans] = useState<{ [key: number]: boolean }>({})

  const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    setSelectedFile(file)
    setLoading(true)
    setError(null)
    setResult(null)  // 清除之前的结果

    const formData = new FormData()
    formData.append('certificate', file)

    try {
      const response = await axios.post('/api/analyze/file', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      })
      if (response.data.success) {
        setResult(response.data.result)
      } else {
        setError(response.data.error || '分析失败')
      }
    } catch (err) {
      setError('请求失败')
    } finally {
      setLoading(false)
    }
  }

  const handleExport = async () => {
    if (!selectedFile) return
    setExportLoading(true)
    setError(null)

    const formData = new FormData()
    formData.append('certificate', selectedFile)

    try {
      const response = await axios.post('/api/export/file', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        responseType: 'blob',
      })

      // 创建下载链接
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `${selectedFile.name.split('.')[0]}_certs.zip`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch (err) {
      setError('导出失败')
    } finally {
      setExportLoading(false)
    }
  }

  const clearFile = () => {
    setSelectedFile(null)
    setResult(null)
    setError(null)
  }

  const toggleSanExpand = (certIndex: number) => {
    setExpandedSans(prev => ({
      ...prev,
      [certIndex]: !prev[certIndex]
    }))
  }

  return (
    <Box>
      <Grid container spacing={2} alignItems="center">
        <Grid item xs>
          <Button
            variant="outlined"
            component="label"
            startIcon={loading ? <CircularProgress size={20} /> : <Upload />}
            disabled={loading}
            fullWidth
            sx={{ 
              height: '56px',
              justifyContent: 'flex-start',
              textAlign: 'left'
            }}
          >
            {loading ? '分析中...' : selectedFile ? selectedFile.name : '选择证书文件'}
            <input
              type="file"
              hidden
              accept=".pem,.crt,.cer"
              onChange={handleFileChange}
              disabled={loading}
            />
          </Button>
        </Grid>
        {selectedFile && (
          <Grid item>
            <Button
              variant="outlined"
              color="secondary"
              onClick={clearFile}
              disabled={loading}
              startIcon={<Clear />}
            >
              清除
            </Button>
          </Grid>
        )}
        {result && (
          <Grid item>
            <Button
              variant="contained"
              color="primary"
              startIcon={exportLoading ? <CircularProgress size={20} color="inherit" /> : <Download />}
              onClick={handleExport}
              disabled={loading || exportLoading}
              sx={{ minWidth: '120px' }}
            >
              {exportLoading ? '导出中...' : '导出证书'}
            </Button>
          </Grid>
        )}
      </Grid>

      {loading && !error && (
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', mt: 4, mb: 2 }}>
          <CircularProgress size={40} />
          <Typography variant="body1" sx={{ ml: 2 }}>
            正在分析证书，请稍候...
          </Typography>
        </Box>
      )}

      {error && (
        <Alert severity="error" sx={{ mt: 2 }}>
          {error}
        </Alert>
      )}

      {result && (
        <Box sx={{ mt: 3 }}>
          <Alert
            severity={
              result.isComplete && result.isTrusted && !result.hasExpired && !result.hasRevoked
                ? 'success'
                : 'error'
            }
            sx={{ mb: 2 }}
          >
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              <Chip
                icon={result.isComplete ? <CheckCircle /> : <Error />}
                label={result.isComplete ? '完整' : '不完整'}
                color={result.isComplete ? 'success' : 'error'}
              />
              <Chip
                icon={result.isTrusted ? <CheckCircle /> : <Error />}
                label={result.isTrusted ? '可信' : '不可信'}
                color={result.isTrusted ? 'success' : 'error'}
              />
              <Chip
                icon={result.hasExpired ? <Warning /> : <CheckCircle />}
                label={result.hasExpired ? '已过期' : '有效'}
                color={result.hasExpired ? 'error' : 'success'}
              />
              {result.hasRevoked && (
                <Chip
                  icon={<Error />}
                  label="已吊销"
                  color="error"
                />
              )}
            </Box>
          </Alert>

          {result.certificates.map((cert, index) => (
            <Card key={index} sx={{ mb: 2 }}>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  证书 {index + 1}
                  {index === 0 ? ' (叶子证书)' : 
                   index === result.certificates.length - 1 ? ' (根证书)' : 
                   ' (中间证书)'}
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" color="textSecondary">
                      通用名称 (CN)
                    </Typography>
                    <Typography variant="body1" gutterBottom>
                      {cert.commonName || '无'}
                    </Typography>

                    <Typography variant="subtitle2" color="textSecondary" sx={{ mt: 2 }}>
                      主题备用名称 (SAN)
                    </Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
                      {cert.subjectAltNames && cert.subjectAltNames.length > 0 ? (
                        <>
                          {(expandedSans[index] ? cert.subjectAltNames : cert.subjectAltNames.slice(0, 2)).map((san, idx) => (
                            <Chip
                              key={idx}
                              label={san}
                              size="small"
                              variant="outlined"
                            />
                          ))}
                          {cert.subjectAltNames.length > 2 && (
                            <IconButton
                              size="small"
                              onClick={() => toggleSanExpand(index)}
                              sx={{ ml: 1 }}
                            >
                              {expandedSans[index] ? <ExpandLess /> : <ExpandMore />}
                            </IconButton>
                          )}
                          {!expandedSans[index] && cert.subjectAltNames.length > 2 && (
                            <Typography variant="body2" color="textSecondary" sx={{ ml: 1, alignSelf: 'center' }}>
                              还有 {cert.subjectAltNames.length - 2} 项
                            </Typography>
                          )}
                        </>
                      ) : (
                        <Typography variant="body1">无</Typography>
                      )}
                    </Box>

                    <Typography variant="subtitle2" color="textSecondary">
                      主题
                    </Typography>
                    <Typography variant="body1" gutterBottom>
                      {cert.subject}
                    </Typography>

                    <Typography variant="subtitle2" color="textSecondary">
                      颁发者
                    </Typography>
                    <Typography variant="body1" gutterBottom>
                      {cert.issuer}
                    </Typography>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" color="textSecondary">
                      序列号
                    </Typography>
                    <Typography variant="body1" gutterBottom>
                      {cert.serialNumber}
                    </Typography>

                    <Typography variant="subtitle2" color="textSecondary">
                      密钥类型
                    </Typography>
                    <Typography variant="body1" gutterBottom>
                      {cert.keyType}
                    </Typography>

                    <Typography variant="subtitle2" color="textSecondary">
                      有效期
                    </Typography>
                    <Typography variant="body1" gutterBottom>
                      {new Date(cert.notBefore).toLocaleString()} 至 {new Date(cert.notAfter).toLocaleString()}
                    </Typography>

                    <Typography variant="subtitle2" color="textSecondary">
                      剩余天数
                    </Typography>
                    <Typography 
                      variant="body1" 
                      color={
                        cert.remainingDays < 0 ? 'error' : 
                        cert.remainingDays <= 60 ? 'error' :
                        cert.remainingDays <= 180 ? 'warning' :
                        'success'
                      }
                      sx={{ 
                        fontWeight: cert.remainingDays <= 180 ? 'bold' : 'normal'
                      }}
                    >
                      {cert.remainingDays < 0 ? '已过期' : `${cert.remainingDays} 天`}
                    </Typography>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          ))}
        </Box>
      )}
    </Box>
  )
} 