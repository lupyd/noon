#!/usr/bin/env node
// Tiny same-origin server for rendering:
//   /__stage/*      -> video/stage/dist (the 1920x1080 stage page)
//   /__out/*        -> video/out (timeline.json etc.)
//   /__beats/*      -> video/beats (recorded clips of the real app)
// The Noon app itself is never served from here: every app frame in the film is
// a recording (beats/), made against the real frontend by scripts/record.mjs.
// Usage: node scripts/serve.mjs [--port 4180]
import http from 'node:http'
import { createReadStream, existsSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.m4a': 'audio/mp4',
  '.wav': 'audio/wav',
  '.pdf': 'application/pdf',
  '.webmanifest': 'application/manifest+json',
  '.txt': 'text/plain; charset=utf-8',
}

export function startServer({ port = 4180 } = {}) {
  const stage = path.join(ROOT, 'stage', 'dist')
  const out = path.join(ROOT, 'out')

  const sendFile = (res, file, req) => {
    const ext = path.extname(file).toLowerCase()
    const st = statSync(file)
    const headers = { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': 'no-cache', 'Accept-Ranges': 'bytes' }
    const range = req.headers.range && /bytes=(\d*)-(\d*)/.exec(req.headers.range)
    if (range) {
      const start = range[1] ? Number(range[1]) : 0
      const end = range[2] ? Number(range[2]) : st.size - 1
      res.writeHead(206, { ...headers, 'Content-Range': `bytes ${start}-${end}/${st.size}`, 'Content-Length': end - start + 1 })
      createReadStream(file, { start, end }).pipe(res)
      return
    }
    res.writeHead(200, { ...headers, 'Content-Length': st.size })
    createReadStream(file).pipe(res)
  }

  const isFile = (p) => existsSync(p) && statSync(p).isFile()

  const server = http.createServer((req, res) => {
    try {
      const url = new URL(req.url, 'http://x')
      const p = decodeURIComponent(url.pathname)
      if (p.startsWith('/__stage/')) {
        let f = path.join(stage, p.slice('/__stage/'.length) || 'index.html')
        if (!f.startsWith(stage)) return res.writeHead(403).end()
        if (!isFile(f)) f = path.join(stage, 'index.html')
        return sendFile(res, f, req)
      }
      if (p.startsWith('/__beats/')) {
        const beats = path.join(ROOT, 'beats')
        const f = path.join(beats, p.slice('/__beats/'.length))
        if (!f.startsWith(beats) || !isFile(f)) return res.writeHead(404).end()
        return sendFile(res, f, req)
      }
      if (p.startsWith('/__out/')) {
        const f = path.join(out, p.slice('/__out/'.length))
        if (!f.startsWith(out) || !isFile(f)) return res.writeHead(404).end()
        return sendFile(res, f, req)
      }
      res.writeHead(404).end()
    } catch (err) {
      res.writeHead(500).end(String(err))
    }
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${port}` }))
  })
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2)
  const get = (n, d) => (args.includes(`--${n}`) ? args[args.indexOf(`--${n}`) + 1] : d)
  startServer({ port: Number(get('port', 4180)) }).then(({ url }) => {
    console.log(`stage:  ${url}/__stage/`)
  })
}
