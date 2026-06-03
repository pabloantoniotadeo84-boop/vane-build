const path = require('path');

const vaneApiUrl = process.env.VANE_API_URL ?? 'http://localhost:3000';
const vaneWsUrl = vaneApiUrl.replace(/^http/, 'ws') + '/v1/ws';

/** @type {import('next').NextConfig} */
const nextConfig = {
  outputFileTracingRoot: path.join(__dirname, '../../'),
  env: {
    NEXT_PUBLIC_VANE_WS_URL: vaneWsUrl,
  },
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${vaneApiUrl}/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
