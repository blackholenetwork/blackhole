export interface PluginState {
  name: string;
  status: 'starting' | 'ready' | 'failed' | 'degraded';
  message: string;
  progress: number;
  started_at: string;
}

export interface SystemStatus {
  status: string;
  ready_apis: Record<string, boolean>;
  plugins: Record<string, PluginState>;
  time: string;
}

export interface Metric {
  name: string;
  value: number;
  unit: string;
  timestamp: string;
}

export interface WebSocketMessage {
  type: 'startup_status' | 'plugin_update' | 'metrics_update';
  plugins?: Record<string, PluginState>;
  plugin?: string;
  status?: PluginState;
  metrics?: Record<string, Metric>;
  time: string;
}