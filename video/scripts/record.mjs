#!/usr/bin/env node
// Beat recorder: screen-records the REAL Noon app like a person would.
//
//   node scripts/record.mjs dm teams      # record beats (see scripts/beats.mjs)
//
// The app is the real frontend, built and served as https://noon.lupyd.com by
// scripts/app.mjs (or NOON_URL, e.g. the vite dev server), against the real API
// in emulator mode; beats sign in through localStorage
// tokens minted by scripts/seed.ts, exactly as the app stores them after OTP.
//
// For each beat: GPU headless Chromium opens the app (light theme: the film is set at noon) at a
// 1536×864 CSS viewport (= the stage window body) at device scale 2 (3072×1728 px, so
// camera push-ins stay crisp), puppeteer drives it through
// the app's own selectors with real mouse moves, clicks and
// keystrokes, and CDP screencast captures every composited frame. Frames are
// re-timed from their timestamps into a constant 60 fps NVENC mp4:
//   beats/<id>.mp4   the clip
//   beats/<id>.json  every action: t (s, clip time), kind, selector, rect (CSS px),
//                    click point; plus the full pointer path and viewport info
// The stage plays these clips and derives camera + cursor from the json.
import { spawnSync } from 'node:child_process'
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { launch, chromePath, GPU_ARGS, GPU_ENV, gpuRenderer } from './lib/capture.mjs'
import { BEATS } from './beats.mjs'
import { startApp } from './app.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const BEAT_DIR = path.join(ROOT, 'beats')
const ids = process.argv.slice(2).filter((a) => !a.startsWith('--'))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const easeInOut = (x) => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2)

async function recordBeat(url, beat, extraArgs = []) {
  // 1536×864 = the stage window body exactly (screencast ignores DPR, so record at 1:1)
  // screencast frames follow the BROWSER device scale (--force-device-scale-factor), not
  // the emulated one, so the DPR is applied at launch
  const V = beat.viewport ?? { width: 1536, height: 864, dpr: 2 }
  const work = path.join(ROOT, '.cache', 'rec', beat.id)
  rmSync(work, { recursive: true, force: true })
  mkdirSync(work, { recursive: true })
  const browser = await launch({
    executablePath: chromePath(),
    headless: true,
    env: { ...process.env, ...GPU_ENV },
    args: [...extraArgs, `--force-device-scale-factor=${V.dpr}`, '--no-sandbox', '--hide-scrollbars', '--force-color-profile=srgb', '--autoplay-policy=no-user-gesture-required', '--mute-audio', '--disable-background-timer-throttling', '--disable-renderer-backgrounding', ...GPU_ARGS],
  })
  try {
    const page = await browser.newPage()
    await page.setViewport({ width: V.width, height: V.height, deviceScaleFactor: V.dpr, isMobile: !!V.mobile, hasTouch: !!V.mobile })
    await page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: 'light' }])
    await page.evaluateOnNewDocument(() => {
      try {
        localStorage.setItem('theme', 'light')
      } catch {}
    })
    page.on('pageerror', (e) => console.warn(`  [${beat.id}] pageerror ${e.message}`))
    // Recording polish (no change to the app itself): the thread's own scroll-to-latest
    // glides instead of jumping, and rows that mount during the take ease in.
    // Rows present before the take started have finished their animation already.
    await page.evaluateOnNewDocument(() => {
      // smooth scrolling is opt-in per beat (rec.smooth()): while a view is still settling the
      // app re-writes scrollTop repeatedly, and smooth behaviour would restart on each write
      const css = `
        html.__rec_smooth * { scroll-behavior: smooth !important; }
        ::-webkit-scrollbar { display: none; }`
      const add = () => {
        const st = document.createElement('style')
        st.textContent = css
        document.head.append(st)
      }
      if (document.head) add()
      else document.addEventListener('DOMContentLoaded', add)
    })
    // sign in the way the app does after an OTP: email + token in localStorage
    if (beat.auth) {
      const auth = await beat.auth()
      await page.evaluateOnNewDocument((a) => {
        for (const [k, v] of Object.entries(a)) localStorage.setItem(k, v)
      }, auth)
    }
    const renderer = await gpuRenderer(page)
    const route = typeof beat.route === 'function' ? await beat.route() : beat.route
    await page.goto(url + route, { waitUntil: 'networkidle2', timeout: 60000 })
    await sleep(beat.settle ?? 1800)

    // ---- logging helpers (clip clock = seconds since the first frame)
    let clock0 = 0
    const now = () => Date.now() / 1000 - clock0
    const actions = []
    const pointer = []
    let mx = beat.cursorStart?.x ?? V.width * 0.62
    let my = beat.cursorStart?.y ?? V.height * 0.55
    const find = async (target) => {
      const h = await page.waitForFunction(
        (sel, src, rowSrc) => {
          const vis = (e) => {
            const r = e.getBoundingClientRect()
            return r.width > 0 && r.height > 0
          }
          const re = src ? new RegExp(src[0], src[1]) : null
          const row = rowSrc ? new RegExp(rowSrc[0], rowSrc[1]) : null
          // row: the element must sit in the smallest ancestor "row" that mentions this text
          const inRow = (e) => {
            let p = e.parentElement
            for (let i = 0; i < 8 && p; i++, p = p.parentElement) if (row.test(p.textContent || '')) return p.querySelectorAll(e.tagName).length <= 3
            return false
          }
          return [...document.querySelectorAll(sel)].filter(vis).find((e) => (!re || re.test((e.textContent || e.getAttribute('aria-label') || '').trim())) && (!row || inRow(e))) || null
        },
        { timeout: 15000 },
        typeof target === 'string' ? target : target.sel,
        typeof target === 'string' || !target.text ? null : [target.text.source, target.text.flags],
        typeof target === 'string' || !target.row ? null : [target.row.source, target.row.flags]
      )
      const el = h.asElement()
      // offscreen? scroll it into view like a person would, then measure
      const off = await el.evaluate((e) => {
        const r = e.getBoundingClientRect()
        return r.top < 0 || r.bottom > innerHeight
      })
      if (off) {
        await el.evaluate((e) => e.scrollIntoView({ block: 'center', behavior: 'smooth' }))
        await sleep(300)
        // long pages take longer than a fixed wait: measure only once it has stopped moving
        let last = ''
        for (let i = 0; i < 40; i++) {
          const r = await el.evaluate((e) => e.getBoundingClientRect().y.toFixed(1))
          if (r === last) break
          last = r
          await sleep(90)
        }
      }
      const rect = await el.evaluate((e) => {
        const r = e.getBoundingClientRect()
        return [r.x, r.y, r.width, r.height]
      })
      return { el, rect }
    }
    const moveTo = async (x, y, ms) => {
      const d = Math.hypot(x - mx, y - my)
      const dur = ms ?? Math.min(700, Math.max(260, d * 0.75))
      const n = Math.max(8, Math.round(dur / 16))
      const x0 = mx
      const y0 = my
      for (let i = 1; i <= n; i++) {
        const p = easeInOut(i / n)
        const arc = Math.sin(p * Math.PI) * Math.min(40, d * 0.08)
        mx = x0 + (x - x0) * p
        my = y0 + (y - y0) * p - arc
        await page.mouse.move(mx, my)
        pointer.push([+now().toFixed(3), +mx.toFixed(1), +my.toFixed(1)])
        await sleep(dur / n)
      }
    }
    const label = (target) => (typeof target === 'string' ? target : `${target.sel} ~/${target.text?.source ?? ''}/`)
    const rec = {
      page,
      sleep,
      async click(target, opts = {}) {
        const { el, rect } = await find(target)
        const x = rect[0] + rect[2] * (opts.fx ?? 0.5)
        const y = rect[1] + rect[3] * (opts.fy ?? 0.5)
        await moveTo(x, y, opts.move)
        await sleep(opts.dwell ?? 90)
        const t = now()
        await page.mouse.down()
        await sleep(70)
        await page.mouse.up()
        actions.push({ t: +t.toFixed(3), kind: 'click', sel: label(target), rect, x, y, name: opts.name })
        void el
        await sleep(opts.after ?? 350)
        return rect
      },
      async hover(target, opts = {}) {
        const { rect } = await find(target)
        await moveTo(rect[0] + rect[2] / 2, rect[1] + rect[3] / 2, opts.move)
        actions.push({ t: +now().toFixed(3), kind: 'hover', sel: label(target), rect, name: opts.name })
        await sleep(opts.after ?? 300)
        return rect
      },
      async type(target, text, opts = {}) {
        const { rect } = await find(target)
        const t = now()
        for (const ch of text) {
          await page.keyboard.type(ch)
          // human cadence: quicker inside words, small pauses at spaces/punctuation
          await sleep((opts.cps ? 1000 / opts.cps : 55) * (ch === ' ' ? 1.6 : /[.,?!]/.test(ch) ? 2.2 : 0.7 + Math.random() * 0.6))
        }
        actions.push({ t: +t.toFixed(3), end: +now().toFixed(3), kind: 'type', sel: label(target), rect, text, name: opts.name })
        await sleep(opts.after ?? 150)
        return rect
      },
      /** paste text into the focused field in one go (like Ctrl+V) */
      async paste(target, text, opts = {}) {
        const { rect } = await find(target)
        actions.push({ t: +now().toFixed(3), kind: 'paste', sel: label(target), rect, text, name: opts.name })
        await page.keyboard.sendCharacter(text)
        await sleep(opts.after ?? 400)
        return rect
      },
      async key(k, opts = {}) {
        actions.push({ t: +now().toFixed(3), kind: 'key', key: k, name: opts.name })
        await page.keyboard.press(k)
        await sleep(opts.after ?? 400)
      },
      async rect(target, name) {
        const { rect } = await find(target)
        actions.push({ t: +now().toFixed(3), kind: 'mark', sel: label(target), rect, name })
        return rect
      },
      /** let the app's own scroll-to-latest glide from here on (call once the view has settled) */
      async smooth(on = true) {
        await page.evaluate((v) => document.documentElement.classList.toggle('__rec_smooth', v), on)
      },
      /** eased programmatic scroll of the main scroller (no wheel bursts) */
      async scroll(to, ms = 900, sel = null) {
        const t = now()
        await page.evaluate(
          (to, ms, sel) =>
            new Promise((done) => {
              const inner = [...document.querySelectorAll('*')].filter((e) => e.scrollHeight > e.clientHeight + 100 && e.clientHeight > 250 && getComputedStyle(e).overflowY !== 'visible').sort((a, b) => b.clientHeight * b.clientWidth - a.clientHeight * a.clientWidth)[0]
              // pages that scroll the document itself (Noon) have no inner scroller
              const sc = sel ? document.querySelector(sel) : inner ?? document.scrollingElement
              if (!sc) return done()
              sc.style.setProperty('scroll-behavior', 'auto', 'important')
              const from = sc.scrollTop
              const target = to === 'top' ? 0 : to === 'bottom' ? sc.scrollHeight - sc.clientHeight : from + to
              const t0 = performance.now()
              const ease = (x) => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2)
              const step = () => {
                const p = Math.min(1, (performance.now() - t0) / ms)
                sc.scrollTop = from + (target - from) * ease(p)
                if (p < 1) requestAnimationFrame(step)
                else {
                  sc.style.removeProperty('scroll-behavior')
                  done()
                }
              }
              requestAnimationFrame(step)
            }),
          to, ms, sel
        )
        actions.push({ t: +t.toFixed(3), end: +now().toFixed(3), kind: 'scroll', name: `scroll` })
      },
      mark(name) {
        actions.push({ t: +now().toFixed(3), kind: 'mark', name })
      },
    }
    if (beat.before) await beat.before(rec)

    // ---- screencast
    const cdp = await page.createCDPSession()
    const frames = []
    let pending = 0
    cdp.on('Page.screencastFrame', (ev) => {
      cdp.send('Page.screencastFrameAck', { sessionId: ev.sessionId }).catch(() => {})
      const file = path.join(work, `f${String(frames.length).padStart(6, '0')}.jpg`)
      frames.push({ file, ts: ev.metadata.timestamp })
      pending++
      import('node:fs').then(({ writeFile }) => writeFile(file, Buffer.from(ev.data, 'base64'), () => pending--))
    })
    await cdp.send('Page.startScreencast', { format: 'jpeg', quality: Number(process.env.REC_Q ?? 80), everyNthFrame: 1, maxWidth: Math.round(V.width * V.dpr), maxHeight: Math.round(V.height * V.dpr) })
    // keep the compositor producing frames even when the page is still
    await page.evaluate(() => {
      const d = document.createElement('div')
      d.style.cssText = 'position:fixed;right:0;bottom:0;width:1px;height:1px;z-index:2147483647;pointer-events:none;background:#000;opacity:0.01'
      document.documentElement.append(d)
      const tick = () => {
        d.style.opacity = d.style.opacity === '0.01' ? '0.02' : '0.01'
        requestAnimationFrame(tick)
      }
      requestAnimationFrame(tick)
    })
    while (!frames.length) await sleep(10)
    clock0 = frames[0].ts
    await sleep(beat.lead ?? 400)
    try {
      await beat.run(rec)
    } catch (e) {
      const shot = path.join(ROOT, '.cache', `rec-fail-${beat.id}.png`)
      await page.screenshot({ path: shot }).catch(() => {})
      throw new Error(`${beat.id}: step after [${actions.map((a) => a.name || a.kind).join(', ')}] failed: ${e.message.split('\n')[0]} (screenshot ${shot})`)
    }
    await sleep(beat.tail ?? 600)
    const end = now()
    await cdp.send('Page.stopScreencast')
    while (pending > 0) await sleep(20)

    // ---- frames → constant 60 fps clip
    const seq = frames.map((f) => ({ ...f, t: f.ts - clock0 })).filter((f) => f.t <= end + 0.05)
    const lines = ['ffconcat version 1.0']
    for (let i = 0; i < seq.length; i++) {
      const b = i + 1 < seq.length ? seq[i + 1].t : end
      if (b - seq[i].t <= 0) continue
      lines.push(`file '${seq[i].file}'`, `duration ${(b - seq[i].t).toFixed(6)}`)
    }
    lines.push(`file '${seq[seq.length - 1].file}'`)
    const list = path.join(work, 'frames.ffconcat')
    writeFileSync(list, lines.join('\n') + '\n')
    mkdirSync(BEAT_DIR, { recursive: true })
    const out = path.join(BEAT_DIR, `${beat.id}.mp4`)
    const r = spawnSync('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-y', '-f', 'concat', '-safe', '0', '-i', list, '-vf', 'fps=60,format=yuv420p', '-t', end.toFixed(3), '-c:v', 'h264_nvenc', '-preset', 'p5', '-cq', '17', '-b:v', '0', '-g', '2', '-bf', '0', '-movflags', '+faststart', out], { stdio: 'inherit' })
    if (r.status !== 0) throw new Error('ffmpeg assemble failed')
    const gaps = seq.slice(1).map((f, i) => f.t - seq[i].t).sort((a, b) => a - b)
    const stats = { frames: seq.length, captureFps: +(seq.length / end).toFixed(1), medianGapMs: +(1000 * gaps[gaps.length >> 1]).toFixed(1), p95GapMs: +(1000 * gaps[Math.floor(gaps.length * 0.95)]).toFixed(1) }
    const meta = { id: beat.id, route, viewport: V, size: [Math.round(V.width * V.dpr), Math.round(V.height * V.dpr)], duration: +end.toFixed(3), renderer, capture: stats, focus: beat.focus ?? null, actions, pointer, recordedAt: new Date().toISOString() }
    writeFileSync(path.join(BEAT_DIR, `${beat.id}.json`), JSON.stringify(meta, null, 1))
    rmSync(work, { recursive: true, force: true })
    return meta
  } finally {
    await browser.close().catch(() => {})
  }
}

const app = process.env.NOON_URL ? null : await startApp()
const url = process.env.NOON_URL ?? app.url
try {
  for (const id of ids.length ? ids : Object.keys(BEATS)) {
    const beat = BEATS[id]
    if (!beat) throw new Error(`unknown beat ${id}`)
    const t0 = Date.now()
    const m = await recordBeat(url, { id, ...beat }, app?.chromeArgs ?? [])
    console.log(`${id}: ${m.duration}s clip, ${m.actions.length} actions, capture ${m.capture.captureFps} fps (median gap ${m.capture.medianGapMs} ms, p95 ${m.capture.p95GapMs} ms) · ${((Date.now() - t0) / 1000).toFixed(1)}s · ${m.renderer}`)
  }
} finally {
  app?.close()
}
