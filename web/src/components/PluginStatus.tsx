import {
  Box,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip
} from '@mui/material';
import { PluginState } from '../types';

interface PluginStatusProps {
  plugins: Record<string, PluginState>;
}

function PluginStatus({ plugins }: PluginStatusProps) {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'ready':
        return 'success';
      case 'failed':
        return 'error';
      default:
        return 'warning';
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom sx={{ mb: 4 }}>
        Plugin Status
      </Typography>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Plugin Name</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Message</TableCell>
              <TableCell>Started At</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {Object.entries(plugins).map(([name, plugin]) => (
              <TableRow key={name}>
                <TableCell>
                  <Typography variant="body1" sx={{ textTransform: 'capitalize', fontWeight: 500 }}>
                    {name}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Chip
                    label={plugin.status}
                    size="small"
                    color={getStatusColor(plugin.status) as any}
                  />
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="text.secondary">
                    {plugin.message}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="text.secondary">
                    {plugin.started_at ? new Date(plugin.started_at).toLocaleString() : '-'}
                  </Typography>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}

export default PluginStatus;
