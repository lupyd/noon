// Render logo/index.html frame by frame into out/logo.mp4.
//   node logo/render.mjs                 full clip at 60 fps
//   node logo/render.mjs --still 0,2,4   PNG stills at those seconds
import { spawn } from 'node:child_process'
import { createReadStream, existsSync, mkdirSync, writeFileSync } from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import puppeteer from 'puppeteer-core'

const ROOT = path.dirname(fileURLToPath(import.meta.url))
const OUT = path.join(ROOT, '..', 'out')
const FPS = 60
const arg = (k) => {
  const i = process.argv.indexOf(`--${k}`)
  return i < 0 ? null : process.argv[i + 1]
}
mkdirSync(OUT, { recursive: true })

const types = { '.html': 'text/html', '.svg': 'image/svg+xml', '.js': 'text/javascript' }
const server = http.createServer((req, res) => {
  const f = path.join(ROOT, decodeURIComponent(new URL(req.url, 'http://x').pathname))
  if (!f.startsWith(ROOT) || !existsSync(f)) return res.writeHead(404).end()
  res.writeHead(200, { 'content-type': types[path.extname(f)] ?? 'application/octet-stream' })
  createReadStream(f).pipe(res)
})
await new Promise((r) => server.listen(0, r))
const url = `http://127.0.0.1:${server.address().port}/index.html`

// Same NVIDIA offload setup as lupyd-demo/video/scripts/lib/capture.mjs.
const gpu = process.env.STAGE_GPU !== '0'
const browser = await puppeteer.launch({
  executablePath: process.env.CHROME_PATH ?? '/usr/sbin/chromium',
  headless: true,
  env: gpu
    ? { ...process.env, __NV_PRIME_RENDER_OFFLOAD: '1', __GLX_VENDOR_LIBRARY_NAME: 'nvidia', __EGL_VENDOR_LIBRARY_FILENAMES: '/usr/share/glvnd/egl_vendor.d/10_nvidia.json' }
    : process.env,
  args: [
    ...(gpu ? ['--enable-gpu', '--ignore-gpu-blocklist', '--use-gl=angle', '--use-angle=gl-egl'] : []),
    '--no-sandbox', '--hide-scrollbars', '--force-color-profile=srgb',
  ],
})
try {
  const page = await browser.newPage()
  page.on('pageerror', (e) => console.error(`[page] ${e.message}`))
  page.on('console', (m) => console.log(`[page] ${m.text()}`))
  await page.setViewport({ width: 1920, height: 1080 })
  await page.goto(url, { waitUntil: 'load' })
  await page.waitForFunction('window.__ready === true', { timeout: 60_000 })
  const duration = await page.evaluate(() => window.__duration)
  const cdp = await page.createCDPSession()
  const shot = async (format) =>
    Buffer.from((await cdp.send('Page.captureScreenshot', { format, quality: format === 'jpeg' ? 95 : undefined, fromSurface: true })).data, 'base64')

  const stills = arg('still')
  if (stills) {
    for (const t of stills.split(',').map(Number)) {
      await page.evaluate((tt) => window.__seek(tt), t)
      const f = path.join(OUT, `logo-${t.toFixed(2)}.png`)
      writeFileSync(f, await shot('png'))
      console.log(f)
    }
  } else {
    const file = path.join(OUT, 'logo.mp4')
    const ff = spawn('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-y', '-f', 'image2pipe', '-framerate', String(FPS), '-c:v', 'mjpeg', '-i', '-',
      '-vf', 'scale=in_range=full:out_range=tv,format=yuv420p', '-c:v', 'libx264', '-preset', 'medium', '-crf', '14', '-pix_fmt', 'yuv420p',
      '-color_primaries', 'bt709', '-color_trc', 'bt709', '-colorspace', 'bt709', file], { stdio: ['pipe', 'inherit', 'inherit'] })
    const closed = new Promise((r) => ff.on('close', r))
    const n = Math.round(duration * FPS)
    const t0 = Date.now()
    for (let i = 0; i < n; i++) {
      await page.evaluate((tt) => window.__seek(tt), i / FPS)
      if (!ff.stdin.write(await shot('jpeg'))) await new Promise((r) => ff.stdin.once('drain', r))
    }
    ff.stdin.end()
    if ((await closed) !== 0) throw new Error('ffmpeg failed')
    console.log(`${file}  ${n} frames in ${((Date.now() - t0) / 1000).toFixed(1)}s`)
  }
} finally {
  await browser.close()
  server.close()
}
