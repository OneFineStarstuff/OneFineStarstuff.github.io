/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: { serverActions: { allowedOrigins: ["*"] } },
  reactStrictMode: true
};
module.exports = nextConfig;
