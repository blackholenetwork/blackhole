import { useEffect, useState } from 'react';
import { Box, Typography, Grid, Paper, CircularProgress } from '@mui/material';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import axios from 'axios';

interface MetricData {
  time: string;
  value: number;
}

function SystemMetrics() {
  const [metrics, setMetrics] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [memoryHistory, setMemoryHistory] = useState<MetricData[]>([]);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const response = await axios.get('/api/metrics');
        setMetrics(response.data);
        setLoading(false);

        // Add to history for chart
        if (response.data['memory.alloc']) {
          setMemoryHistory(prev => {
            const newData = [...prev, {
              time: new Date().toLocaleTimeString(),
              value: Math.round(response.data['memory.alloc'].value / 1024 / 1024) // Convert to MB
            }];
            // Keep last 20 data points
            return newData.slice(-20);
          });
        }
      } catch (error) {
        console.error('Failed to fetch metrics:', error);
        setLoading(false);
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);

    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  const formatBytes = (bytes: number) => {
    const mb = bytes / 1024 / 1024;
    return `${mb.toFixed(2)} MB`;
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom sx={{ mb: 4 }}>
        System Metrics
      </Typography>

      <Grid container spacing={3}>
        {/* Memory Stats */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Memory Usage
            </Typography>
            {metrics && metrics['memory.alloc'] && (
              <Box>
                <Typography variant="h3" color="primary">
                  {formatBytes(metrics['memory.alloc'].value)}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Current allocation
                </Typography>
              </Box>
            )}
          </Paper>
        </Grid>

        {/* Goroutines */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Active Goroutines
            </Typography>
            {metrics && metrics['runtime.goroutines'] && (
              <Box>
                <Typography variant="h3" color="secondary">
                  {metrics['runtime.goroutines'].value}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Concurrent operations
                </Typography>
              </Box>
            )}
          </Paper>
        </Grid>

        {/* Memory Chart */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Memory Usage Over Time
            </Typography>
            <Box sx={{ height: 300, mt: 2 }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={memoryHistory}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                  <XAxis dataKey="time" stroke="#666" />
                  <YAxis stroke="#666" label={{ value: 'Memory (MB)', angle: -90, position: 'insideLeft' }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1e1e1e', border: '1px solid #333' }}
                    labelStyle={{ color: '#fff' }}
                  />
                  <Line
                    type="monotone"
                    dataKey="value"
                    stroke="#00bcd4"
                    strokeWidth={2}
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </Box>
          </Paper>
        </Grid>

        {/* All Metrics Grid */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              All Metrics
            </Typography>
            <Grid container spacing={2} sx={{ mt: 1 }}>
              {metrics && Object.entries(metrics).map(([key, metric]: [string, any]) => (
                <Grid item xs={12} sm={6} md={4} key={key}>
                  <Box sx={{ p: 2, border: '1px solid #333', borderRadius: 1 }}>
                    <Typography variant="caption" color="text.secondary">
                      {key}
                    </Typography>
                    <Typography variant="body1">
                      {typeof metric.value === 'number'
                        ? metric.unit === 'bytes'
                          ? formatBytes(metric.value)
                          : `${metric.value} ${metric.unit || ''}`
                        : metric.value
                      }
                    </Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}

export default SystemMetrics;
