// v3 scenes (DIRECTION.md): the stage only frames and edits recorded clips of
// the real app. Camera moves and the cursor are derived from the beat logs
// (beats/<id>.json); static is the default. No pills, glows or overlays.
import { el, LOGO_PATH, LOGO_TRANSFORM, svgNS } from '../dom'
import { clamp, lerp, spring } from '../motion'
import type { SceneBuilder } from '../types'

// ---------------------------------------------------------------- types
export type Rect = [number, number, number, number]
export interface Action { t: number; kind: string; name?: string; rect?: Rect; x?: number; y?: number; end?: number }
export interface BeatMeta {
  id: string
  viewport: { width: number; height: number; dpr: number; mobile?: boolean }
  size: [number, number]
  duration: number
  actions: Action[]
  pointer: [number, number, number][]
  focus: { on: string; until: string; zmax?: number } | null
  pop?: string[]
  in: number
  out: number
  src: string
}

// ---------------------------------------------------------------- easing
/** cubic-bezier(x1,y1,x2,y2) as a function of progress */
export function bezier(x1: number, y1: number, x2: number, y2: number) {
  const cx = 3 * x1, bx = 3 * (x2 - x1) - cx, ax = 1 - cx - bx
  const cy = 3 * y1, by = 3 * (y2 - y1) - cy, ay = 1 - cy - by
  const sx = (t: number) => ((ax * t + bx) * t + cx) * t
  const sy = (t: number) => ((ay * t + by) * t + cy) * t
  const dx = (t: number) => (3 * ax * t + 2 * bx) * t + cx
  return (x: number) => {
    if (x <= 0) return 0
    if (x >= 1) return 1
    let t = x
    for (let i = 0; i < 8; i++) {
      const e = sx(t) - x
      const d = dx(t)
      if (Math.abs(e) < 1e-6 || Math.abs(d) < 1e-6) break
      t -= e / d
    }
    return sy(clamp(t))
  }
}
export const easeOutExpoish = bezier(0.22, 1, 0.36, 1)
export const PUSH = 0.8 // s, push-in / pull-out duration

// ---------------------------------------------------------------- layout
/** the one hero window: ~80% of the frame, centred */
const WIN = { x: 192, y: 81, w: 1536, bar: 36 }
const bodyH = (b: BeatMeta) => Math.round((WIN.w * b.viewport.height) / b.viewport.width)

function windowChrome(b: BeatMeta) {
  const h = bodyH(b)
  const win = el('div', { class: 'v3-win', style: `left:${WIN.x}px;top:${WIN.y}px;width:${WIN.w}px;height:${h + WIN.bar}px` })
  const bar = el('div', { class: 'v3-bar' }, el('i', { class: 'r' }), el('i', { class: 'y' }), el('i', { class: 'g' }))
  const video = el('video', { muted: true, playsinline: true, preload: 'auto', src: b.src, style: `width:${WIN.w}px;height:${h}px` }) as HTMLVideoElement
  video.muted = true
  win.append(bar, video)
  return { win, video, body: { x: WIN.x, y: WIN.y + WIN.bar, w: WIN.w, h } }
}

/** deterministic seek of a clip to `ct` seconds (frame-centred) */
export async function seekVideo(v: HTMLVideoElement, ct: number) {
  if (v.readyState < 1) {
    if (v.networkState === HTMLMediaElement.NETWORK_EMPTY || v.preload === 'none') v.load()
    await new Promise<void>((r) => {
      v.addEventListener('loadedmetadata', () => r(), { once: true })
      setTimeout(r, 8000)
    })
  }
  // seek to the CENTRE of the 60 fps source frame: seeking exactly onto a frame
  // boundary lets the decoder pick either neighbour, which reads as a jitter
  const want = clamp((Math.floor(ct * 60 + 1e-6) + 0.5) / 60, 0, Math.max(0, v.duration - 0.02))
  if (Math.abs(v.currentTime - want) < 0.001 && v.readyState >= 2) return
  await new Promise<void>((r) => {
    const done = () => r()
    v.addEventListener('seeked', done, { once: true })
    v.currentTime = want
    setTimeout(done, 3000)
  })
}

// ---------------------------------------------------------------- camera
export interface View { x: number; y: number; z: number }
export const FULL: View = { x: 960, y: 540, z: 1 }
/** a logged rect → push-in view: rect padded 2.2×, 16:9, clamped inside the window */
export function focusView(r: Rect, map: (x: number, y: number) => { x: number; y: number }, body: { x: number; y: number; w: number; h: number }, scale: number, zmax = 2.4): View {
  const a = map(r[0], r[1])
  const w0 = r[2] * scale * 2.2
  const h0 = r[3] * scale * 2.2
  const w = Math.max(w0, (h0 * 16) / 9, 560)
  const z = clamp(1920 / w, 1, zmax)
  const hw = 960 / z
  const hh = 540 / z
  const cx0 = a.x + (r[2] * scale) / 2
  const cy0 = a.y + (r[3] * scale) / 2
  const fit = (c: number, lo: number, size: number, half: number) => (size <= half * 2 ? lo + size / 2 : clamp(c, lo + half, lo + size - half))
  return { x: fit(cx0, body.x, body.w, hw), y: fit(cy0, body.y - WIN.bar, body.h + WIN.bar, hh), z }
}
export function mixView(a: View, b: View, p: number): View {
  return { x: lerp(a.x, b.x, p), y: lerp(a.y, b.y, p), z: Math.exp(lerp(Math.log(a.z), Math.log(b.z), p)) }
}

// ---------------------------------------------------------------- cursor
export const CURSOR_SVG = `<svg width="26" height="26" viewBox="0 0 28 28"><path d="M5.5 3.2v19.6c0 .6.7.9 1.1.5l4.6-4.6 3.2 7.2c.2.4.6.6 1 .4l2.6-1.1c.4-.2.6-.6.4-1l-3.2-7.1h6.4c.6 0 .9-.7.5-1.1L6.6 2.7c-.4-.4-1.1-.1-1.1.5z" fill="#111" stroke="#fff" stroke-width="1.6" stroke-linejoin="round"/></svg>`
export function pointerAt(p: [number, number, number][], t: number) {
  if (!p.length) return null
  if (t <= p[0][0]) return { x: p[0][1], y: p[0][2] }
  let lo = 0
  let hi = p.length - 1
  while (hi - lo > 1) {
    const m = (lo + hi) >> 1
    if (p[m][0] <= t) lo = m
    else hi = m
  }
  const a = p[lo]
  const b = p[hi]
  if (t >= b[0]) return { x: b[1], y: b[2] }
  const k = (t - a[0]) / Math.max(1e-6, b[0] - a[0])
  return { x: lerp(a[1], b[1], k), y: lerp(a[2], b[2], k) }
}

// ---------------------------------------------------------------- scenes
/** fade-in for the 200 ms cross-dissolve (outgoing scene stays opaque underneath) */
const dissolve = (root: HTMLElement, lt: number) => (root.style.opacity = clamp((lt + 0.2) / 0.2).toFixed(3))

export const clip: SceneBuilder = ({ root, s }) => {
  const b = (s as any).beat as BeatMeta
  const world = el('div', { class: 'world' })
  root.append(world)
  const { win, video, body } = windowChrome(b)
  world.append(win)
  const scale = body.w / b.viewport.width
  const map = (x: number, y: number) => ({ x: body.x + x * scale, y: body.y + y * scale })
  const act = (n?: string) => b.actions.find((a) => a.name === n)

  // camera: at most one push-in, on the named action's logged rect
  let push: { a: number; b: number; view: View } | null = null
  if (b.focus) {
    const on = act(b.focus.on)
    const until = act(b.focus.until) ?? on
    const rect = on?.rect ?? b.actions.filter((x) => x.rect && x.t <= (on?.t ?? 0)).pop()?.rect
    if (on && rect) push = { a: on.t - 0.4 - PUSH, b: (until?.end ?? until?.t ?? on.t) + 0.3, view: focusView(rect, map, body, scale, b.focus.zmax) }
  }

  // cursor + click ripples from the recording (no clicks → no cursor)
  const clicks = b.actions.filter((a) => a.kind === 'click' && a.rect)
  const cursor = el('div', { class: 'v3-cursor', html: CURSOR_SVG })
  const ripple = el('div', { class: 'v3-ripple' })
  if (clicks.length) world.append(ripple, cursor)
  const curOn = clicks.length ? [Math.max(b.in, (b.pointer[0]?.[0] ?? clicks[0].t) - 0.25), clicks[clicks.length - 1].t + 0.6] : [0, -1]

  // channel rows lift in sequence (pixels copied from the clip itself)
  const pops = (b.pop ?? []).map((n) => act(n)).filter((a): a is Action => !!a?.rect)
  const popEls = pops.map((a) => {
    const r = a.rect!
    const p = map(r[0], r[1])
    const c = el('canvas', { class: 'v3-pop', width: Math.round(r[2] * scale * 2), height: Math.round(r[3] * scale * 2), style: `left:${p.x}px;top:${p.y}px;width:${r[2] * scale}px;height:${r[3] * scale}px` }) as HTMLCanvasElement
    world.append(c)
    return { a, c, ctx: c.getContext('2d')! }
  })
  const popT0 = (act('list')?.t ?? 0) + 0.25

  const update = (lt: number) => {
    dissolve(root, lt)
    const ct = b.in + lt
    // camera
    let v = FULL
    if (push) {
      const pin = easeOutExpoish(clamp((ct - push.a) / PUSH))
      const pout = easeOutExpoish(clamp((ct - push.b) / PUSH))
      v = mixView(mixView(FULL, push.view, pin), FULL, pout)
    }
    world.style.transform = `translate(960px, 540px) scale(${v.z.toFixed(5)}) translate(${(-v.x).toFixed(2)}px, ${(-v.y).toFixed(2)}px)`
    // cursor
    if (clicks.length) {
      const p = pointerAt(b.pointer, ct)
      const on = ct >= curOn[0] && ct <= curOn[1] && p
      cursor.style.opacity = on ? '1' : '0'
      if (p) {
        const q = map(p.x, p.y)
        const press = clicks.some((c) => ct >= c.t - 0.02 && ct < c.t + 0.12)
        cursor.style.transform = `translate(${(q.x - 5).toFixed(1)}px, ${(q.y - 3).toFixed(1)}px) scale(${press ? 0.88 : 1})`
      }
      const last = [...clicks].reverse().find((c) => ct >= c.t && ct < c.t + 0.55)
      if (last) {
        const r = last.rect!
        const q = map(r[0] + r[2] / 2, r[1] + r[3] / 2)
        const k = (ct - last.t) / 0.55
        ripple.style.transform = `translate(${q.x.toFixed(1)}px, ${q.y.toFixed(1)}px) scale(${(0.35 + 1.1 * k).toFixed(3)})`
        ripple.style.opacity = ((1 - k) * 0.85).toFixed(3)
      } else ripple.style.opacity = '0'
    }
    // channel pops: lift + settle, one after another
    popEls.forEach(({ c, ctx }, i) => {
      const tl = ct - (popT0 + i * 0.16)
      const k = tl > 0 && tl < 0.9 ? spring(tl, { stiffness: 260, damping: 16 }) * (1 - clamp((tl - 0.45) / 0.45)) : 0
      c.style.opacity = k > 0.01 ? '1' : '0'
      c.style.transform = `translateY(${(-3 * k).toFixed(2)}px) scale(${(1 + 0.06 * k).toFixed(4)})`
      c.style.boxShadow = `0 ${(10 * k).toFixed(1)}px ${(26 * k).toFixed(1)}px rgba(0,0,0,${(0.5 * k).toFixed(3)})`
      if (k > 0.01) {
        const r = popEls[i].a.rect!
        const sx = (video.videoWidth || b.size[0]) / b.viewport.width
        ctx.drawImage(video, r[0] * sx, r[1] * sx, r[2] * sx, r[3] * sx, 0, 0, c.width, c.height)
      }
    })
  }
  ;(update as any).seek = (lt: number) => seekVideo(video, b.in + lt)
  return update
}

/** one centred phone, entirely inside the frame; the screen is the real app at 390×844 */
export const phone: SceneBuilder = ({ root, s }) => {
  const b = (s as any).beat as BeatMeta
  const SH = 1080 - 2 * 36 - 2 * 12
  const k = SH / b.viewport.height
  const SW = Math.round(b.viewport.width * k)
  const R = Math.round(47 * k)
  const ph = el('div', { class: 'v3-phone', style: `left:${960 - SW / 2 - 12}px;top:${36}px;width:${SW + 24}px;height:${SH + 24}px;border-radius:${R + 12}px` })
  const video = el('video', { muted: true, playsinline: true, preload: 'auto', src: b.src, style: `width:${SW}px;height:${SH}px;border-radius:${R}px` }) as HTMLVideoElement
  video.muted = true
  ph.append(video)
  root.append(ph)
  const update = (lt: number) => dissolve(root, lt)
  ;(update as any).seek = (lt: number) => seekVideo(video, b.in + lt)
  return update
}

/** large, single-line kinetic type cards, one at a time (≤ 1.6 s each) */
export const typecard: SceneBuilder = ({ root, s, dur }) => {
  const cards = ((s as any).cards as string[]).map((txt) => {
    const e = el('div', { class: 'v3-type' }, txt)
    root.append(e)
    return e
  })
  const each = dur / cards.length
  return (lt) => {
    dissolve(root, lt)
    cards.forEach((e, i) => {
      const a = lt - i * each
      const on = a >= 0 && a < each
      const p = spring(a, { stiffness: 180, damping: 22 })
      e.style.opacity = on ? clamp(p * 1.4).toFixed(3) : '0'
      e.style.transform = `translate(-50%, -50%) translateY(${((1 - p) * 26).toFixed(2)}px)`
    })
  }
}

export function logo(size: number) {
  const s = document.createElementNS(svgNS, 'svg')
  s.setAttribute('viewBox', '0 0 800 800')
  s.setAttribute('width', String(size))
  s.setAttribute('height', String(size))
  s.innerHTML = `<circle cx="400" cy="400" r="400" fill="#fff"/><g transform="${LOGO_TRANSFORM}"><path fill="#000" d="${LOGO_PATH}"/></g>`
  return s
}

/** the Lupyd mark forms, the wordmark wipes in (also used for the end card) */
export const brand: SceneBuilder = ({ root, s, dur }) => {
  const mark = el('div', { class: 'v3-mark' }, logo(132))
  const word = el('div', { class: 'v3-word' }, 'Lupyd')
  const lockup = el('div', { class: 'v3-lockup' }, mark, word)
  const tag = el('div', { class: 'v3-tag' }, (s as any).tagline ?? '')
  const url = el('div', { class: 'v3-url' }, (s as any).url ?? '')
  root.append(lockup, tag, url)
  return (lt) => {
    dissolve(root, lt)
    const m = spring(lt - 0.05, { stiffness: 200, damping: 20 })
    mark.style.transform = `scale(${(0.6 + 0.4 * m).toFixed(4)})`
    mark.style.opacity = clamp(m * 1.5).toFixed(3)
    const w = clamp((lt - 0.25) / 0.5)
    word.style.clipPath = `inset(0 ${((1 - easeOutExpoish(w)) * 100).toFixed(2)}% 0 0)`
    const tg = spring(lt - 0.75, { stiffness: 180, damping: 22 })
    tag.style.opacity = (s as any).tagline ? clamp(tg * 1.4).toFixed(3) : '0'
    tag.style.transform = `translate(-50%, 0) translateY(${((1 - tg) * 16).toFixed(1)}px)`
    const u = spring(lt - 1.15, { stiffness: 180, damping: 22 })
    url.style.opacity = (s as any).url ? clamp(u * 1.4).toFixed(3) : '0'
    void dur
  }
}
