const path = require('path');

const counselApiUrl = process.env.COUNSEL_API_URL ?? 'http://localhost:3000';
const counselWsUrl = counselApiUrl.replace(/^http/, 'ws') + '/v1/ws';

/** @type {import('next').NextConfig} */
const nextConfig = {
  outputFileTracingRoot: path.join(__dirname, '../../'),
  env: {
    NEXT_PUBLIC_COUNSEL_WS_URL: counselWsUrl,
  },
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${counselApiUrl}/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
