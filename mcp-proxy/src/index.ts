import { loadConfig } from './config';
import { createProxyServer } from './server';

const config = loadConfig();

createProxyServer(config).listen(config.port, () => {
  config.log({ level: 'info', msg: 'anonymizing MCP proxy listening', port: config.port, upstream: config.upstreamUrl });
});
