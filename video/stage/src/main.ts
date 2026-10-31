import './style.css'
import { css, div, el } from './dom'
import { runSeekHooksSync, setKeepMounted, syncFrames } from './frames'
import { clamp, ease, hash, lerp, noise1, prog } from './motion'
import type { SceneAPI, SceneT, Timeline } from './types'
import { SCENES } from './scenes/index'
import { CUES } from './cues'

declare global {
  interface Window {
    __seek: (t: number) => Promise<void>
    __ready: boolean
    __duration: number
    __timeline: Timeline
    __error?: string
    __cues: unknown
    __prepareAll: (from?: number, to?: number) => Promise<void>
    __play: (from?: number, to?: number) => Promise<{ frames: number; start: number }>
    __realtime?: boolean
  }
}

let PRE = 0.7 // seconds a scene is alive before its start; must exceed frame lead-in (0.65s) so iframes never load in a display:none scene
let POST = 0.7

// mood colours for the background glow, per scene: [blobA, blobB, blobC, intensity]
// Noon lives in the logo's night navy; the moods only tint it per scene (fire
// warmth for the problem, a cooler cast for the cryptography).
const MOODS: Record<string, [string, string, string, number]> = {
  intro: ['#2c2a70', '#1b1a4a', '#3a2a6a', 0.5],
  problem: ['#5a2030', '#241c4a', '#3a1f3a', 0.5],
  create: ['#2e3480', '#1c1d4c', '#3a2d72', 0.55],
  respond: ['#33307a', '#1d2252', '#4a2d6e', 0.55],
  blind: ['#1d4a5a', '#1e1f52', '#2f3a7a', 0.55],
  results: ['#2e3480', '#1c1d4c', '#3a2d72', 0.55],
  cta: ['#2c2a70', '#1b1a4a', '#3a2a6a', 0.5],
}

function hexToRgb(h: string) {
  const n = parseInt(h.slice(1), 16)
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
}
function mixHex(a: string, b: string, t: number) {
  const A = hexToRgb(a)
  const B = hexToRgb(b)
  return `rgb(${A.map((v, i) => Math.round(lerp(v, B[i], t))).join(',')})`
}

function grainTile(seed: number) {
  const c = document.createElement('canvas')
  c.width = c.height = 256
  const g = c.getContext('2d')!
  const img = g.createImageData(256, 256)
  for (let i = 0; i < 256 * 256; i++) {
    const v = Math.floor(hash(i * 1.37 + seed * 101.3) * 255)
    img.data[i * 4] = img.data[i * 4 + 1] = img.data[i * 4 + 2] = v
    img.data[i * 4 + 3] = 255
  }
  g.putImageData(img, 0, 0)
  return c.toDataURL()
}

async function boot() {
  const thumbMode = new URLSearchParams(location.search).has('thumb')
  const tl: Timeline = thumbMode
    ? { bpm: 108, beat: 60 / 108, bar: 240 / 108, duration: 20, scenes: [{ id: 'thumb', start: 0, end: 20, bars: 9, endCard: 0, lines: [] }] }
    : await fetch('/__out/timeline.json', { cache: 'no-store' }).then((r) => r.json())
  window.__timeline = tl
  window.__duration = tl.duration
  const stage = document.getElementById('stage')!
  // v3 (record-then-edit): scenes only overlap for the 200 ms dissolve, and the
  // background is one static gradient (no blurred blobs / grain to re-raster)
  const v3 = (tl as any).v >= 3
  const v4 = (tl as any).v >= 4
  if (v3) PRE = POST = 0.25
  // v5: strictly sequential scenes — nothing from the next shot exists before its cut
  if ((tl as any).v >= 5) PRE = POST = 0

  // --- background
  const bg = div(v4 ? 'layer v4-bg' : v3 ? 'layer v3-bg' : 'layer')
  // v4: soft colour fields (radial gradients — no blur filters) drifting under a sheen
  const fields = v4 ? [0, 1, 2, 3].map(() => el('div', { class: 'm' })) : []
  const sheen = v4 ? el('div', { class: 'sheen' }) : null
  if (v4) bg.append(...fields, sheen!, el('div', { class: 'floor' }))
  // night to noon: the night sky covers the daylight until the sunrise, which
  // sweeps up from below the frame into the cut to the first product shot
  const night = el('div', { class: 'noon-night' })
  const dawn = el('div', { class: 'noon-dawn' })
  bg.append(night, dawn)
  const SUNRISE = (tl.scenes.find((x) => x.id === 'create')?.start ?? 0) - 0.9
  const sky = (t: number) => {
    const k = ease.inOutCubic(prog(t, SUNRISE, SUNRISE + 1.3))
    const R = k * 2700 - 300 // radius of the daylight, centred below the frame
    const at = 'circle at 50% 118%'
    const hole = `radial-gradient(${at}, transparent ${R.toFixed(0)}px, #000 ${(R + 320).toFixed(0)}px)`
    css(night, { display: k >= 1 ? 'none' : '', maskImage: hole, webkitMaskImage: hole } as any)
    css(dawn, {
      opacity: k > 0 && k < 1 ? '1' : '0',
      background: `radial-gradient(${at}, rgba(249,211,99,0) ${(R - 260).toFixed(0)}px, rgba(239,141,44,0.55) ${(R + 40).toFixed(0)}px, rgba(231,91,50,0.38) ${(R + 220).toFixed(0)}px, rgba(184,44,51,0) ${(R + 520).toFixed(0)}px)`,
    })
  }
  const blobs = [0, 1, 2].map((i) => {
    const b = el('div', { class: 'bg-blob', style: `width:${[1100, 900, 800][i]}px;height:${[900, 800, 700][i]}px` })
    bg.append(b)
    return b
  })
  stage.append(bg)
  const scenesLayer = div('layer')
  stage.append(scenesLayer)
  const grain = el('div', { class: 'grain', style: `background-image:url(${grainTile(7)})` })
  const vignette = div('vignette')
  const fade = el('div', { class: 'layer', style: 'background:#000;opacity:0' })
  if (v3) {
    blobs.forEach((b) => b.remove())
    stage.append(fade)
  } else stage.append(vignette, grain, fade)

  // --- scenes
  const live: { s: SceneT; root: HTMLElement; update: (lt: number, t: number) => void; seek?: (lt: number) => Promise<void> }[] = []
  for (const s of tl.scenes) {
    const builder = SCENES[(s as any).kind ?? s.id]
    if (!builder) continue
    const root = el('div', { class: 'scene', 'data-scene': s.id })
    scenesLayer.append(root)
    const api: SceneAPI = {
      root,
      s,
      tl,
      dur: s.end - s.start,
      L: (id: string) => {
        const l = s.lines.find((x) => x.id === id)
        if (!l) throw new Error(`no line ${id} in ${s.id}`)
        return { start: l.start - s.start, end: l.end - s.start }
      },
      beat: tl.beat,
      bar: tl.bar,
    }
    const update = builder(api)
    live.push({ s, root, update, seek: (update as any).seek })
  }

  const moodAt = (t: number) => {
    const sc = tl.scenes
    let i = sc.findIndex((s) => t < s.end)
    if (i < 0) i = sc.length - 1
    const cur = MOODS[sc[i].id] ?? MOODS.intro
    const prev = i > 0 ? MOODS[sc[i - 1].id] ?? cur : cur
    const k = ease.inOutCubic(prog(t, sc[i].start - 0.2, sc[i].start + 1.4))
    return { a: mixHex(prev[0], cur[0], k), b: mixHex(prev[1], cur[1], k), c: mixHex(prev[2], cur[2], k), I: lerp(prev[3], cur[3], k) }
  }

  const fontsReady = document.fonts.ready
  const updateAll = (t: number) => {
    if (v4) {
      sky(t)
      const m = moodAt(t)
      const cols = [m.a, m.b, m.c, m.a]
      const P = [
        [520 + noise1(t * 0.05, 1) * 300, 300 + noise1(t * 0.04, 2) * 180, 1500],
        [1450 + noise1(t * 0.045, 3) * 280, 760 + noise1(t * 0.05, 4) * 160, 1400],
        [1150 + noise1(t * 0.05, 5) * 320, 120 + noise1(t * 0.04, 6) * 140, 1100],
        [260 + noise1(t * 0.04, 7) * 200, 900 + noise1(t * 0.05, 8) * 120, 1000],
      ]
      fields.forEach((f, i) => {
        const [x, y, r] = P[i]
        css(f, { width: `${r}px`, height: `${r}px`, transform: `translate(${(x - r / 2).toFixed(1)}px, ${(y - r / 2).toFixed(1)}px)`, background: `radial-gradient(closest-side, ${cols[i]}, transparent)`, opacity: (m.I * [1, 0.85, 0.7, 0.5][i]).toFixed(3) })
      })
      css(sheen!, { transform: `translateX(${(((t * 0.08) % 1) * 140 - 70).toFixed(2)}%)` })
    }
    if (v3) {
      css(fade, { opacity: (1 - ease.outCubic(prog(t, 0, 0.5))).toFixed(3) })
      for (const sc of live) {
        const lt = t - sc.s.start
        const alive = lt >= -PRE && lt <= sc.s.end - sc.s.start + POST
        css(sc.root, { display: alive ? '' : 'none' })
        if (alive) sc.update(lt, t)
      }
      return
    }
    const m = moodAt(t)
    const pos = [
      [560 + noise1(t * 0.07, 1) * 260, 380 + noise1(t * 0.06, 2) * 160],
      [1400 + noise1(t * 0.05, 3) * 260, 700 + noise1(t * 0.07, 4) * 180],
      [1100 + noise1(t * 0.06, 5) * 300, 200 + noise1(t * 0.05, 6) * 160],
    ]
    const cols = [m.a, m.b, m.c]
    blobs.forEach((b, i) => {
      const w = b.offsetWidth || 1000
      const h = b.offsetHeight || 800
      css(b, {
        transform: `translate(${(pos[i][0] - w / 2).toFixed(1)}px, ${(pos[i][1] - h / 2).toFixed(1)}px)`,
        background: `radial-gradient(circle at 50% 50%, ${cols[i]}, transparent 65%)`,
        opacity: (m.I * [1, 0.8, 0.7][i]).toFixed(3),
      })
    })
    const f = Math.floor(t * 30)
    css(grain, { backgroundPosition: `${Math.floor(hash(f) * 256)}px ${Math.floor(hash(f + 0.5) * 256)}px` })
    // global fade in from black at the very start
    css(fade, { opacity: (1 - ease.outCubic(prog(t, 0, 0.8))).toFixed(3) })

    for (const sc of live) {
      const lt = t - sc.s.start
      const alive = lt >= -PRE && lt <= sc.s.end - sc.s.start + POST
      css(sc.root, { display: alive ? '' : 'none' })
      if (alive) sc.update(lt, t)
    }
  }

  window.__seek = async (t: number) => {
    t = clamp(t, 0, tl.duration)
    await fontsReady
    updateAll(t) // set visibility first (iframes need a laid-out host)
    await syncFrames(t)
    await Promise.all(live.filter((sc) => sc.seek && t - sc.s.start >= -PRE && t - sc.s.start <= sc.s.end - sc.s.start + POST).map((sc) => sc.seek!(t - sc.s.start)))
    updateAll(t) // re-run with frame metadata available
  }
  // --- realtime playback (render.mjs default mode) -------------------------
  // Load every iframe the range needs up front (each inside its visible scene,
  // so layouts match the deterministic path), keep them mounted, then play the
  // timeline against the clock. Each rAF applies the frame synchronously.
  window.__prepareAll = async (from = 0, to = tl.duration) => {
    setKeepMounted(true)
    window.__realtime = true
    for (let t = from; t <= to; t += 0.5) await window.__seek(t)
    await window.__seek(from)
  }
  window.__play = (from = 0, to = tl.duration) =>
    new Promise((resolve) => {
      const p0 = performance.now()
      const start = Date.now()
      let frames = 0
      const tick = () => {
        const t = from + (performance.now() - p0) / 1000
        updateAll(Math.min(t, to))
        runSeekHooksSync(Math.min(t, to))
        frames++
        if (t >= to) return resolve({ frames, start })
        requestAnimationFrame(tick)
      }
      requestAnimationFrame(tick)
    })
  // preload stage images
  await Promise.all([...document.images].map((im) => im.decode().catch(() => {})))
  await fontsReady
  Object.defineProperty(window, '__cues', { get: () => [...CUES].sort((a, b) => a.t - b.t) })
  window.__ready = true
}

boot().catch((e) => {
  console.error(e)
  window.__error = String(e?.stack || e)
})
