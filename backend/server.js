#!/usr/bin/env node
import process from 'node:process'
import express from 'express'
import helmet from 'helmet'
import cors from 'cors'
import compression from 'compression'
import morgan from 'morgan'
import dotenv from 'dotenv'
import mongoSanitize from 'express-mongo-sanitize'
import xss from 'xss'
import hpp from 'hpp'
import crypto from 'node:crypto'

dotenv.config()

const app = express()

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ['\'self\''],
      styleSrc: ['\'self\'', '\'unsafe-inline\'', 'https://fonts.googleapis.com'],
      fontSrc: ['\'self\'', 'https://fonts.gstatic.com'],
      scriptSrc: ['\'self\''],
      imgSrc: ['\'self\'', 'data:', 'https:'],
      connectSrc: ['\'self\''],
      frameSrc: ['\'none\''],
      objectSrc: ['\'none\''],
      mediaSrc: ['\'self\''],
      workerSrc: ['\'none\'']
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}))

app.use(cors())
app.use(compression())
app.use(morgan('dev'))

app.use(express.json({
  limit: '10mb',
  verify: (req, _res, buf) => {
    req.rawBody = buf
  }
}))

app.use(mongoSanitize({
  replaceWith: '_'
}))

app.use(hpp())

app.use((req, _res, next) => {
  if (req.body) {
    Object.keys(req.body).forEach((key) => {
      if (typeof req.body[key] === 'string') {
        req.body[key] = xss(req.body[key])
      }
    })
  }
  next()
})

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' })
})

app.use((req, res, next) => {
  req.id = crypto.randomUUID()
  req.timestamp = new Date().toISOString()
  res.setHeader('X-Request-ID', req.id)
  next()
})

app.get('/api/wheel/stages', async (_req, res) => {
  const stages = [
    {
      id: 1,
      title: 'Creative Remembering',
      symbol: '🌱'
    }
  ]
  res.json({
    success: true,
    data: stages,
    timestamp: new Date().toISOString()
  })
})

const PORT = process.env.PORT || 4200
app.listen(PORT, () => {
  process.stdout.write('Server running\n')
})

export default app
