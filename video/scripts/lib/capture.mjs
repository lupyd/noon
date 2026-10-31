// Shared headless-Chromium plumbing for render.mjs / frames.mjs / thumbnail.mjs
import { existsSync } from 'node:fs'
import puppeteer from 'puppeteer-core'

const CHROME = [process.env.CHROME_PATH, '/usr/sbin/chromium', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome-stable', '/usr/bin/google-chrome'].filter(Boolean)

export function chromePath() {
  const p = CHROME.find((c) => existsSync(c))
  if (!p) throw new Error('No Chromium found; set CHROME_PATH')
  return p
}

// Every browser / child process the pipeline starts is tracked here and
// SIGKILLed on exit, Ctrl-C, SIGTERM (e.g. `timeout`) or a crash: try/finally
// alone does not run on signals, which is how headless Chromium got orphaned.
const tracked = new Set()
export function track(proc) {
  if (proc) tracked.add(proc)
  return proc
}
export function untrack(proc) {
  tracked.delete(proc)
}
function killAll() {
  for (const p of tracked) {
    try {
      p.kill('SIGKILL')
    } catch {}
  }
  tracked.clear()
}
process.on('exit', killAll)
for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(sig, () => (killAll(), process.exit(130)))
process.on('uncaughtException', (e) => (console.error(e), killAll(), process.exit(1)))
process.on('unhandledRejection', (e) => (console.error(e), killAll(), process.exit(1)))

export async function launch(opts) {
  const browser = await puppeteer.launch(opts)
  const proc = browser.process()
  track(proc)
  browser.on('disconnected', () => untrack(proc))
  return browser
}

// GPU: rasterise/composite on the NVIDIA dGPU instead of SwiftShader. On this
// hybrid laptop EGL defaults to the AMD iGPU, so glvnd/PRIME are pointed at the
// NVIDIA driver. STAGE_GPU=0 falls back to the CPU path.
export const useGpu = process.env.STAGE_GPU !== '0'
export const GPU_ARGS = ['--enable-gpu', '--ignore-gpu-blocklist', '--enable-gpu-rasterization', '--enable-zero-copy', '--use-gl=angle', '--use-angle=gl-egl', // hardware video decode fails (MEDIA_ERR_DECODE) on this ANGLE/EGL path
  '--disable-accelerated-video-decode']
export const GPU_ENV = {
  __NV_PRIME_RENDER_OFFLOAD: '1',
  __GLX_VENDOR_LIBRARY_NAME: 'nvidia',
  __EGL_VENDOR_LIBRARY_FILENAMES: '/usr/share/glvnd/egl_vendor.d/10_nvidia.json',
  VK_ICD_FILENAMES: '/usr/share/vulkan/icd.d/nvidia_icd.json',
}

export async function gpuRenderer(page) {
  return page.evaluate(() => {
    const g = document.createElement('canvas').getContext('webgl')
    const e = g?.getExtension('WEBGL_debug_renderer_info')
    return g ? (e ? g.getParameter(e.UNMASKED_RENDERER_WEBGL) : g.getParameter(g.RENDERER)) : 'no webgl'
  })
}

export async function openStage(base, { scale = 1, log = false, query = '' } = {}) {
  const browser = await launch({
    executablePath: chromePath(),
    headless: true,
    protocolTimeout: 600_000,
    env: useGpu ? { ...process.env, ...GPU_ENV } : process.env,
    args: [
      ...(useGpu ? GPU_ARGS : []),
      '--no-sandbox',
      '--disable-dev-shm-usage',
      '--hide-scrollbars',
      '--mute-audio',
      '--force-color-profile=srgb',
      '--font-render-hinting=none',
      '--autoplay-policy=no-user-gesture-required',
      '--disable-background-timer-throttling',
      '--disable-renderer-backgrounding',
      '--disable-backgrounding-occluded-windows',
      '--disable-features=CalculateNativeWinOcclusion,PaintHolding',
      '--run-all-compositor-stages-before-draw',
    ],
  })
  const page = await browser.newPage()
  await page.setViewport({ width: 1920, height: 1080, deviceScaleFactor: scale })
  if (log) page.on('console', (m) => console.log(`[stage] ${m.text()}`))
  page.on('pageerror', (e) => console.error(`[stage error] ${e.message}`))
  await page.goto(`${base}/__stage/${query}`, { waitUntil: 'load', timeout: 120_000 })
  await page.waitForFunction('window.__ready === true || !!window.__error', { timeout: 120_000 })
  const err = await page.evaluate(() => window.__error)
  if (err) throw new Error(`stage failed: ${err}`)
  const duration = await page.evaluate(() => window.__duration)
  const cdp = await page.createCDPSession()
  // captureScreenshot composites a fresh frame from the current DOM, so no rAF
  // round-trips are needed after the seek (STAGE_RAF=1 restores them)
  const raf = process.env.STAGE_RAF === '1'
  const seek = async (t) => {
    await page.evaluate(async (tt, rf) => {
      await window.__seek(tt)
      if (rf) await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))
    }, t, raf)
  }
  const shot = async (format = 'jpeg', quality = 90) => {
    const { data } = await cdp.send('Page.captureScreenshot', { format, quality: format === 'jpeg' ? quality : undefined, optimizeForSpeed: true, fromSurface: true, captureBeyondViewport: false })
    return Buffer.from(data, 'base64')
  }
  const renderer = await gpuRenderer(page)
  if (useGpu && !/NVIDIA/i.test(renderer)) console.warn(`[stage] GPU requested but renderer is: ${renderer}`)
  return { browser, page, seek, shot, duration, renderer }
}
