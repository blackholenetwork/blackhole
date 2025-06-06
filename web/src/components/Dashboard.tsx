import { Grid, Paper, Box, Typography, LinearProgress, Chip } from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  HourglassEmpty as HourglassIcon
} from '@mui/icons-material';
import { PluginState } from '../types';

interface DashboardProps {
  plugins: Record<string, PluginState>;
  connected: boolean;
}

function Dashboard({ plugins, connected }: DashboardProps) {
  const pluginArray = Object.entries(plugins);
  const readyCount = pluginArray.filter(([_, p]) => p.status === 'ready').length;
  const totalProgress = pluginArray.length > 0
    ? Math.round((readyCount * 100) / pluginArray.length)
    : 0;

  const isSystemReady = readyCount === pluginArray.length && pluginArray.length > 0;

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

  return (
    <Box>
      <Typography variant="h4" gutterBottom sx={{ mb: 4 }}>
        System Overview
      </Typography>

      {/* Overall Progress */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Startup Progress
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Box sx={{ flexGrow: 1 }}>
            <LinearProgress
              variant="determinate"
              value={totalProgress}
              sx={{ height: 10, borderRadius: 5 }}
            />
          </Box>
          <Typography variant="body2" color="text.secondary" sx={{ minWidth: 50 }}>
            {totalProgress}%
          </Typography>
        </Box>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          {isSystemReady ? '✅ All systems operational' : `${readyCount} of ${pluginArray.length} plugins ready`}
        </Typography>
      </Paper>

      {/* Plugin Status Grid */}
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

      {/* Connection Status */}
      <Paper sx={{ p: 3, mt: 3 }}>
        <Typography variant="h6" gutterBottom>
          Connection Status
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
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
          <Typography>
            WebSocket: {connected ? 'Connected' : 'Disconnected'}
          </Typography>
        </Box>
      </Paper>
    </Box>
  );
}

export default Dashboard;
