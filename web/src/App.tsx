import { useEffect, useState } from 'react';
import { ThemeProvider, createTheme, CssBaseline } from '@mui/material';
import { Box, Container, Typography, AppBar, Toolbar } from '@mui/material';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import PluginStatus from './components/PluginStatus';
import SystemMetrics from './components/SystemMetrics';
import { useWebSocket } from './hooks/useWebSocket';
import { PluginState } from './types';

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00bcd4',
    },
    secondary: {
      main: '#ff4081',
    },
    background: {
      default: '#121212',
      paper: '#1e1e1e',
    },
  },
  typography: {
    fontFamily: '"Roboto Mono", "Roboto", "Helvetica", "Arial", sans-serif',
  },
});

function App() {
  const [plugins, setPlugins] = useState<Record<string, PluginState>>({});
  const { connected, lastMessage } = useWebSocket('ws://localhost:8080/ws');

  useEffect(() => {
    if (lastMessage) {
      try {
        const data = JSON.parse(lastMessage);
        if (data.type === 'startup_status' || data.type === 'plugin_update') {
          setPlugins(data.plugins || {});
        }
      } catch (err) {
        console.error('Failed to parse WebSocket message:', err);
      }
    }
  }, [lastMessage]);

  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Router>
        <Box sx={{ flexGrow: 1 }}>
          <AppBar position="static" sx={{ background: '#1a1a1a' }}>
            <Toolbar>
              <Typography variant="h6" component="div" sx={{ flexGrow: 1, fontWeight: 600 }}>
                Blackhole Network Dashboard
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Box
                  sx={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    backgroundColor: connected ? '#4caf50' : '#f44336',
                  }}
                />
                <Typography variant="body2" color="text.secondary">
                  {connected ? 'Connected' : 'Disconnected'}
                </Typography>
              </Box>
            </Toolbar>
          </AppBar>

          <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
            <Routes>
              <Route path="/" element={
                <Dashboard plugins={plugins} connected={connected} />
              } />
              <Route path="/plugins" element={
                <PluginStatus plugins={plugins} />
              } />
              <Route path="/metrics" element={
                <SystemMetrics />
              } />
            </Routes>
          </Container>
        </Box>
      </Router>
    </ThemeProvider>
  );
}

export default App;
