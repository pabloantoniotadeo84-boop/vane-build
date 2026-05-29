const path = require('path');

/** @type {import('next').NextConfig} */
const nextConfig = {
  outputFileTracingRoot: path.join(__dirname, '../../'),
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${process.env.COUNSEL_API_URL ?? 'http://localhost:3000'}/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
