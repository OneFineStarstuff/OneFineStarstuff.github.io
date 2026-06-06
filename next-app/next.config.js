const nextConfig = {
  experimental: {
    serverActions: {
      allowedOrigins: ['*']
    }
  },
  images: {
    unoptimized: true
  },
  reactStrictMode: true
}

module.exports = nextConfig
