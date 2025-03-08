import { useState } from 'react'
import {
  Box,
  TextField,
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
import { CheckCircle, Error, Warning, Search, ExpandMore, ExpandLess } from '@mui/icons-material'
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

export default function DomainAnalyzer() {
  const [domain, setDomain] = useState('')
  const [ip, setIp] = useState('')
  const [port, setPort] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [expandedSans, setExpandedSans] = useState<{ [key: number]: boolean }>({})

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const payload: {
        domain: string
        ip?: string
        port?: string
      } = {
        domain
      }

      // 只有当 IP 和端口都不为空时，才添加到请求中
      if (ip.trim() && port.trim()) {
        payload.ip = ip.trim()
        payload.port = port.trim()
      }

      const response = await axios.post('/api/analyze/domain', payload)
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
    try {
      const payload: {
        domain: string
        ip?: string
        port?: string
      } = {
        domain
      }

      if (ip.trim() && port.trim()) {
        payload.ip = ip.trim()
        payload.port = port.trim()
      }

      const response = await axios.post('/api/export', payload, {
        responseType: 'blob'
      })
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `${domain}-certificates.zip`)
      document.body.appendChild(link)
      link.click()
      link.remove()
    } catch (err) {
      setError('导出失败')
    }
  }

  // 验证端口号格式
  const validatePort = (value: string) => {
    const portNum = parseInt(value)
    return value === '' || (!isNaN(portNum) && portNum >= 1 && portNum <= 65535)
  }

  // 验证 IP 地址格式
  const validateIP = (value: string) => {
    if (value === '') return true
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/
    if (!ipRegex.test(value)) return false
    return value.split('.').every(num => {
      const n = parseInt(num)
      return n >= 0 && n <= 255
    })
  }

  const toggleSanExpand = (certIndex: number) => {
    setExpandedSans(prev => ({
      ...prev,
      [certIndex]: !prev[certIndex]
    }))
  }

  return (
    <Box>
      <form onSubmit={handleSubmit}>
        <Grid container spacing={2}>
          <Grid item xs={12}>
            <TextField
              fullWidth
              label="域名"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="请输入域名，例如: example.com"
              disabled={loading}
              error={!!error}
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              label="IP 地址（可选）"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="例如: 192.168.1.1"
              disabled={loading}
              error={!validateIP(ip)}
              helperText={!validateIP(ip) ? "请输入有效的 IP 地址" : ""}
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              label="端口号（可选）"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              placeholder="例如: 443"
              disabled={loading}
              error={!validatePort(port)}
              helperText={!validatePort(port) ? "端口号必须在 1-65535 之间" : ""}
            />
          </Grid>
          <Grid item xs={12}>
            <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-start' }}>
              <Button
                variant="contained"
                type="submit"
                disabled={loading || !domain.trim() || !validateIP(ip) || !validatePort(port)}
                startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <Search />}
                sx={{ minWidth: '120px' }}
              >
                {loading ? '分析中...' : '分析证书'}
              </Button>
              {result && (
                <Button
                  variant="outlined"
                  onClick={handleExport}
                  disabled={loading}
                  startIcon={loading ? <CircularProgress size={20} /> : undefined}
                >
                  导出证书
                </Button>
              )}
            </Box>
          </Grid>
        </Grid>
      </form>

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