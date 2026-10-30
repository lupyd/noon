// The real Noon frontend as the recorder sees it: a production build of
// ../frontend served over HTTPS as https://noon.lupyd.com, with
// https://api.noon.lupyd.com proxied to the local emulator API. Chromium maps
// both hosts to this server (host-resolver-rules) and accepts its self-signed
// certificate, so every URL the app shows on screen is the production one.
//
//   const app = await startApp()   // { url, chromeArgs, close }
//   node scripts/app.mjs --build    // rebuild the frontend first
import { spawnSync } from 'node:child_process'
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync } from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const FRONTEND = path.resolve(ROOT, '..', 'frontend')
const DIST = path.join(ROOT, '.cache', 'app-dist')
const TLS = path.join(ROOT, '.cache', 'tls')
const API = { host: '127.0.0.1', port: Number(process.env.NOON_API_PORT ?? 39210) }
const PORT = 8443
export const APP_HOST = 'noon.lupyd.com'
export const API_HOST = 'api.noon.lupyd.com'

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.webp': 'image/webp', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.png': 'image/png', '.txt': 'text/plain' }

export function buildApp(force = false) {
  if (!force && existsSync(path.join(DIST, 'index.html'))) return
  const r = spawnSync('pnpm', ['exec', 'vite', 'build', '--outDir', DIST, '--emptyOutDir'], {
    cwd: FRONTEND,
    stdio: 'inherit',
    env: { ...process.env, NOON_API_URL: `https://${API_HOST}` },
  })
  if (r.status !== 0) throw new Error('frontend build failed')
}

function cert() {
  mkdirSync(TLS, { recursive: true })
  const key = path.join(TLS, 'key.pem')
  const crt = path.join(TLS, 'cert.pem')
  if (!existsSync(crt)) {
    const r = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650', '-keyout', key, '-out', crt, '-subj', `/CN=${APP_HOST}`, '-addext', `subjectAltName=DNS:${APP_HOST},DNS:${API_HOST}`], { stdio: 'ignore' })
    if (r.status !== 0) throw new Error('openssl failed')
  }
  return { key: readFileSync(key), cert: readFileSync(crt) }
}

export async function startApp() {
  buildApp()
  const server = https.createServer(cert(), (req, res) => {
    if ((req.headers.host ?? '').startsWith(API_HOST)) {
      const up = http.request({ ...API, method: req.method, path: req.url, headers: { ...req.headers, host: `${API.host}:${API.port}` } }, (r) => {
        res.writeHead(r.statusCode ?? 502, r.headers)
        r.pipe(res)
      })
      up.on('error', (e) => res.writeHead(502).end(String(e)))
      return req.pipe(up)
    }
    const p = decodeURIComponent(new URL(req.url, 'https://x').pathname)
    let f = path.join(DIST, p)
    if (!f.startsWith(DIST) || !existsSync(f) || !statSync(f).isFile()) f = path.join(DIST, 'index.html') // SPA fallback
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] ?? 'application/octet-stream', 'Cache-Control': 'no-cache' })
    createReadStream(f).pipe(res)
  })
  await new Promise((r) => server.listen(PORT, '127.0.0.1', r))
  return {
    url: `https://${APP_HOST}`,
    chromeArgs: [`--host-resolver-rules=MAP ${APP_HOST} 127.0.0.1:${PORT}, MAP ${API_HOST} 127.0.0.1:${PORT}`, '--ignore-certificate-errors'],
    close: () => server.close(),
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  buildApp(process.argv.includes('--build'))
  const app = await startApp()
  console.log(`${app.url} (chromium: ${app.chromeArgs.join(' ')})`)
}
