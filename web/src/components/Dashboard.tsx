import { useState, useEffect, useRef } from 'react';
import { Grid, Paper, Box, Typography, LinearProgress, Chip, List, ListItem, ListItemText } from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  HourglassEmpty as HourglassIcon,
  Memory as MemoryIcon,
  Speed as SpeedIcon
} from '@mui/icons-material';
import { PluginState, StartupLogResponse, StartupLogEvent } from '../types';
import axios from 'axios';

interface DashboardProps {
  plugins: Record<string, PluginState>;
  connected: boolean;
  lastMessage?: string;
}

interface SystemInfo {
  memory_alloc?: number;
  memory_total?: number;
  goroutines?: number;
  cpu_count?: number;
}

function Dashboard({ plugins, connected, lastMessage }: DashboardProps) {
  const [startupEvents, setStartupEvents] = useState<StartupLogEvent[]>([]);
  const [systemInfo, setSystemInfo] = useState<SystemInfo>({});
  const logEndRef = useRef<HTMLDivElement>(null);

  // Fetch startup log on mount
  useEffect(() => {
    const fetchStartupLog = async () => {
      try {
        const response = await axios.get<StartupLogResponse>('/api/startup-log');
        if (response.data.events) {
          setStartupEvents(response.data.events);
        }
      } catch (error) {
        console.error('Failed to fetch startup log:', error);
      }
    };

    fetchStartupLog();
  }, []);

  // Handle incoming WebSocket messages for real-time startup events
  useEffect(() => {
    if (lastMessage) {
      try {
        const data = JSON.parse(lastMessage);
        if (data.type === 'startup_event' && data.startup_event) {
          // Convert real-time event to log format
          const logEvent: StartupLogEvent = {
            timestamp: new Date().toLocaleString('en-US', {
              year: 'numeric',
              month: '2-digit',
              day: '2-digit',
              hour12: false,
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
              fractionalSecondDigits: 6
            } as any).replace(',', ''),
            type: data.startup_event.event.toUpperCase(),
            plugin: data.startup_event.plugin,
            message: data.startup_event.message,
            raw: `${new Date().toISOString()} [${data.startup_event.event.toUpperCase()}] ${data.startup_event.plugin}: ${data.startup_event.message}`
          };
          setStartupEvents(prev => [...prev, logEvent]); // Append to existing log
        }
      } catch (err) {
        // Ignore parse errors
      }
    }
  }, [lastMessage]);

  // Auto-scroll to bottom when new events arrive
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [startupEvents]);


  // Fetch system information
  useEffect(() => {
    const fetchSystemInfo = async () => {
      try {
        const response = await axios.get('/api/metrics');
        const metrics = response.data;
        setSystemInfo({
          memory_alloc: metrics['memory.alloc']?.value,
          memory_total: metrics['memory.sys']?.value,
          goroutines: metrics['runtime.goroutines']?.value,
          cpu_count: metrics['runtime.cpu_count']?.value
        });
      } catch (error) {
        console.error('Failed to fetch system info:', error);
      }
    };

    fetchSystemInfo();
    const interval = setInterval(fetchSystemInfo, 5000);
    return () => clearInterval(interval);
  }, []);

  const pluginArray = Object.entries(plugins);
  const startedCount = pluginArray.filter(([_, p]) => p.status !== 'starting').length;
  const readyCount = pluginArray.filter(([_, p]) => p.status === 'ready').length;
  const totalCount = pluginArray.length;

  // Startup progress based on plugins that have moved past 'starting' status
  const startupProgress = totalCount > 0
    ? Math.round((startedCount * 100) / totalCount)
    : 0;

  const isSystemReady = readyCount === totalCount && totalCount > 0;

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'ready':
        return <CheckCircleIcon sx={{ color: '#4caf50' }} />;
      case 'failed':
        return <ErrorIcon sx={{ color: '#f44336' }} />;
      case 'degraded':
        return <ErrorIcon sx={{ color: '#ff9800' }} />;
      default:
        return <HourglassIcon sx={{ color: '#ff9800' }} />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'ready':
        return 'success';
      case 'failed':
        return 'error';
      case 'degraded':
        return 'warning';
      default:
        return 'warning';
    }
  };

  const getEventColor = (eventType?: string) => {
    if (!eventType) return '#9e9e9e';

    switch (eventType.toUpperCase()) {
      case 'STARTED':
        return '#4caf50';
      case 'FAILED':
        return '#f44336';
      case 'STOPPED':
        return '#ff9800';
      case 'REGISTERED':
      case 'INITIALIZED':
        return '#2196f3';
      case 'ORCHESTRATOR':
        return '#9c27b0'; // Purple for orchestrator state transitions
      case 'SYSTEM':
        return '#00bcd4';
      default:
        return '#9e9e9e';
    }
  };

  const formatBytes = (bytes?: number) => {
    if (!bytes) return 'N/A';
    const mb = bytes / 1024 / 1024;
    return `${mb.toFixed(2)} MB`;
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom sx={{ mb: 4 }}>
        System Overview
      </Typography>

      {/* System Information - Moved to top */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          System Information
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6} md={3}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <SpeedIcon color="info" />
              <Box>
                <Typography variant="body2" color="text.secondary">
                  CPU Cores
                </Typography>
                <Typography variant="h6">
                  {systemInfo.cpu_count || 'N/A'}
                </Typography>
              </Box>
            </Box>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <MemoryIcon color="primary" />
              <Box>
                <Typography variant="body2" color="text.secondary">
                  Memory Usage
                </Typography>
                <Typography variant="h6">
                  {formatBytes(systemInfo.memory_alloc)}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  of {formatBytes(systemInfo.memory_total)}
                </Typography>
              </Box>
            </Box>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <SpeedIcon color="secondary" />
              <Box>
                <Typography variant="body2" color="text.secondary">
                  Goroutines
                </Typography>
                <Typography variant="h6">
                  {systemInfo.goroutines || 'N/A'}
                </Typography>
              </Box>
            </Box>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Box
                sx={{
                  width: 12,
                  height: 12,
                  borderRadius: '50%',
                  backgroundColor: connected ? '#4caf50' : '#f44336',
                  animation: connected ? 'pulse 2s infinite' : 'none',
                  '@keyframes pulse': {
                    '0%': { opacity: 1 },
                    '50%': { opacity: 0.5 },
                    '100%': { opacity: 1 },
                  },
                }}
              />
              <Box>
                <Typography variant="body2" color="text.secondary">
                  WebSocket
                </Typography>
                <Typography variant="h6">
                  {connected ? 'Connected' : 'Disconnected'}
                </Typography>
              </Box>
            </Box>
          </Grid>
        </Grid>
      </Paper>

      {/* Startup Progress - Based on actual plugin startup status */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Startup Progress
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
          <Box sx={{ flexGrow: 1 }}>
            <LinearProgress
              variant="determinate"
              value={startupProgress}
              sx={{ height: 10, borderRadius: 5 }}
            />
          </Box>
          <Typography variant="body2" color="text.secondary" sx={{ minWidth: 50 }}>
            {startupProgress}%
          </Typography>
        </Box>
        <Typography variant="body2" color="text.secondary">
          {isSystemReady
            ? '✅ All systems operational'
            : `${startedCount} of ${totalCount} plugins initialized`}
        </Typography>

        {/* Startup Sequence Log */}
        <Box sx={{ mt: 2 }}>
          <Typography variant="subtitle2" color="text.secondary" gutterBottom>
            Startup Sequence Log:
          </Typography>
          <Box sx={{
            maxHeight: 200,
            overflowY: 'auto',
            bgcolor: 'background.default',
            borderRadius: 1,
            p: 1,
            border: '1px solid',
            borderColor: 'divider',
            fontFamily: 'monospace',
            fontSize: '0.75rem'
          }}>
            {startupEvents.length === 0 ? (
              <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                Waiting for startup events...
              </Typography>
            ) : (
              <List dense sx={{ py: 0 }}>
                {startupEvents.map((event, index) => (
                  <ListItem key={index} sx={{ py: 0.25, px: 0 }}>
                    <ListItemText
                      sx={{ my: 0 }}
                      primary={
                        event.type === 'SYSTEM' ? (
                          // System message formatting
                          <Box component="span" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Typography
                              component="span"
                              variant="caption"
                              sx={{
                                fontFamily: 'monospace',
                                color: 'text.secondary',
                                minWidth: 140
                              }}
                            >
                              {event.timestamp}
                            </Typography>
                            <Typography
                              component="span"
                              variant="caption"
                              sx={{
                                fontFamily: 'monospace',
                                color: getEventColor('SYSTEM'),
                                fontWeight: 600
                              }}
                            >
                              {event.message}
                            </Typography>
                          </Box>
                        ) : (
                          // Regular event formatting
                          <Box component="span" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Typography
                              component="span"
                              variant="caption"
                              sx={{
                                fontFamily: 'monospace',
                                color: 'text.secondary',
                                minWidth: 140
                              }}
                            >
                              {event.timestamp}
                            </Typography>
                            <Typography
                              component="span"
                              variant="caption"
                              sx={{
                                fontFamily: 'monospace',
                                color: getEventColor(event.type),
                                fontWeight: 600,
                                minWidth: 80
                              }}
                            >
                              [{event.type || 'INFO'}]
                            </Typography>
                            <Typography
                              component="span"
                              variant="caption"
                              sx={{
                                fontFamily: 'monospace',
                                color: 'primary.main',
                                minWidth: 120
                              }}
                            >
                              {event.plugin || 'system'}
                            </Typography>
                            <Typography
                              component="span"
                              variant="caption"
                              sx={{
                                fontFamily: 'monospace',
                                color: 'text.primary'
                              }}
                            >
                              {event.message || event.raw}
                            </Typography>
                          </Box>
                        )
                      }
                    />
                  </ListItem>
                ))}
                <div ref={logEndRef} />
              </List>
            )}
          </Box>
        </Box>
      </Paper>

      {/* Plugin Health - Renamed from Plugin Status */}
      <Typography variant="h5" gutterBottom sx={{ mt: 4, mb: 2 }}>
        Plugin Health
      </Typography>
      <Grid container spacing={3}>
        {pluginArray.map(([name, plugin]) => (
          <Grid item xs={12} sm={6} md={4} key={name}>
            <Paper sx={{ p: 3, height: '100%' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  {getStatusIcon(plugin.status)}
                  <Typography variant="h6" sx={{ textTransform: 'capitalize' }}>
                    {name}
                  </Typography>
                </Box>
                <Chip
                  label={plugin.status}
                  size="small"
                  color={getStatusColor(plugin.status) as any}
                />
              </Box>

              <Typography variant="body2" color="text.secondary">
                {plugin.message}
              </Typography>

              {plugin.started_at && (
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
                  Started: {new Date(plugin.started_at).toLocaleTimeString()}
                </Typography>
              )}
            </Paper>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
}

export default Dashboard;
