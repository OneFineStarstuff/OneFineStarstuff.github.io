const nextConfig = {
  experimental: {
    serverActions: {
      allowedOrigins: ['*']
    }
  },
  reactStrictMode: true,
  images: {
    unoptimized: true
  }
}

module.exports = nextConfig
