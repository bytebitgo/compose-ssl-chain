import { useState } from 'react'
import { Container, Box, Typography, Paper, Tabs, Tab } from '@mui/material'
import { ThemeProvider, createTheme } from '@mui/material/styles'
import CssBaseline from '@mui/material/CssBaseline'
import DomainAnalyzer from './components/DomainAnalyzer'
import FileAnalyzer from './components/FileAnalyzer'

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
})

function App() {
  const [tabValue, setTabValue] = useState(0)

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue)
  }

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Container maxWidth="lg">
        <Box sx={{ my: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom align="center">
            SSL 证书链分析工具
          </Typography>
          <Paper sx={{ mt: 3 }}>
            <Tabs
              value={tabValue}
              onChange={handleTabChange}
              indicatorColor="primary"
              textColor="primary"
              centered
            >
              <Tab label="域名分析" />
              <Tab label="证书文件分析" />
            </Tabs>
            <Box sx={{ p: 3 }}>
              {tabValue === 0 && <DomainAnalyzer />}
              {tabValue === 1 && <FileAnalyzer />}
            </Box>
          </Paper>
        </Box>
      </Container>
    </ThemeProvider>
  )
}

export default App
