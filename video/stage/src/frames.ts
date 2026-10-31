// Iframe pool. Each Frame is a real demo page living in a fixed host element.
// It is mounted only while the timeline needs it, and __seek awaits mounting +
// settling, so any frame of the video can be rendered from a cold start.
import { css, div, el, icon } from './dom'

export type Theme = 'dark' | 'light'

export interface FrameCtx {
  win: Window & { __stageFreeze?: () => void }
  doc: Document
  meta: Record<string, any>
  frame: Frame
}

export interface FrameOpts {
  route: string
  theme?: Theme
  w?: number
  h?: number
  /** absolute timeline seconds during which the iframe must be loaded */
  active: [number, number]
  /** extra CSS injected into the page */
  css?: string
  /** ms to let the app settle after load (data fetch, lazy media) */
  settle?: number
  /** runs once after settle, before freeze: scroll, click tabs, measure */
  prepare?: (ctx: FrameCtx) => Promise<void> | void
  /** runs every seek while mounted: deterministic, time-driven DOM edits */
  onSeek?: (ctx: FrameCtx, t: number) => Promise<void> | void
  /**
   * Real interactions with the app at absolute times (clicks, typing, nav).
   * They are replayed in order from a fresh load whenever a seek needs them,
   * so any frame renders the same from a cold start. Seeking backwards past an
   * applied step reloads the page.
   */
  steps?: Step[]
}

export interface Step {
  /** absolute timeline seconds */
  at: number
  /** element the cursor aims at / the default action presses */
  target?: string | ((doc: Document) => Element | null)
  /** default: press the target */
  run?: (ctx: FrameCtx, el: HTMLElement | null) => Promise<void> | void
  /** ms to let the app react before refreezing (default 450) */
  settle?: number
}

export type Rect = [number, number, number, number]
const rectOf = (e: Element | null | undefined): Rect | null => {
  if (!e) return null
  const r = e.getBoundingClientRect()
  return r.width || r.height ? [r.x, r.y, r.width, r.height] : null
}
export const center = (r: Rect | null | undefined, fx = 0.5, fy = 0.5) => (r ? { x: r[0] + r[2] * fx, y: r[1] + r[3] * fy } : null)

const registry: Frame[] = []
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

export class Frame {
  iframe: HTMLIFrameElement | null = null
  meta: Record<string, any> = {}
  ready = false
  applied = 0
  private pending: Promise<void> | null = null
  readonly w: number
  readonly h: number
  constructor(public host: HTMLElement, public o: FrameOpts) {
    this.w = o.w ?? 1280
    this.h = o.h ?? 800
    registry.push(this)
  }
  wanted(t: number) {
    return t >= this.o.active[0] - 0.05 && t <= this.o.active[1] + 0.05
  }
  ctx(): FrameCtx {
    return { win: this.iframe!.contentWindow as any, doc: this.iframe!.contentDocument!, meta: this.meta, frame: this }
  }
  mount(): Promise<void> {
    if (this.ready) return Promise.resolve()
    if (this.pending) return this.pending
    this.pending = (async () => {
      const f = el('iframe', { width: this.w, height: this.h, scrolling: 'no' }) as HTMLIFrameElement
      f.style.width = `${this.w}px`
      f.style.height = `${this.h}px`
      f.name = JSON.stringify({ lupydStage: 1, theme: this.o.theme ?? 'dark', css: this.o.css ?? '' })
      const loaded = new Promise<void>((r) => f.addEventListener('load', () => r(), { once: true }))
      f.src = this.o.route
      this.host.appendChild(f)
      this.iframe = f
      await loaded
      await settle(f, this.o.settle ?? 1400)
      const c = this.ctx()
      if (this.o.prepare) {
        try {
          await this.o.prepare(c)
        } catch (e) {
          console.warn('prepare failed', this.o.route, e)
        }
      }
      await waitImages(c.doc, 3000)
      c.win.__stageFreeze?.()
      await sleep(80)
      this.ready = true
      this.pending = null
    })()
    return this.pending
  }
  unmount() {
    if (!this.iframe) return
    this.iframe.src = 'about:blank'
    this.iframe.remove()
    this.iframe = null
    this.ready = false
    this.pending = null
    this.applied = 0
    // keep step target rects: they are pure functions of the replayed state
    this.meta = { rects: this.meta.rects ?? {} }
  }
  resolve(doc: Document, target: Step['target']): HTMLElement | null {
    if (!target) return null
    if (typeof target === 'function') return (target(doc) as HTMLElement) ?? null
    const m = target.match(/^(.*?)\s*~\/(.*)\/$/) // "button ~/^Save$/" → by text
    const w = doc.defaultView as any
    return m ? w.__find(m[1], m[2]) : w.__find(target, null)
  }
  /** apply every step with at <= t (replaying from a reload if we went back) */
  async advance(t: number) {
    const steps = this.o.steps
    if (!steps?.length) return
    const want = steps.filter((st) => st.at <= t + 1e-6).length
    if (want < this.applied) {
      this.unmount()
      await this.mount()
    }
    const rects = (this.meta.rects ??= {}) as Record<number, Rect | null>
    while (this.applied < want) {
      const i = this.applied
      const st = steps[i]
      const c = this.ctx()
      ;(c.win as any).__stageThaw?.()
      const el = this.resolve(c.doc, st.target)
      rects[i] = rectOf(el) ?? rects[i] ?? null
      try {
        if (st.run) await st.run(c, el)
        else if (el) (c.win as any).__press(el)
        else console.warn('step target missing', this.o.route, i, String(st.target))
      } catch (e) {
        console.warn('step failed', this.o.route, i, e)
      }
      await sleep(st.settle ?? 450)
      await quiet(c.doc, 6, 100)
      await waitImages(c.doc, 2000)
      c.win.__stageFreeze?.()
      this.applied++
    }
    // where the next step's target sits now (cursor/camera aim before the click)
    if (this.applied < steps.length) {
      const c = this.ctx()
      const nx = steps[this.applied]
      if (nx.target && rects[this.applied] === undefined) rects[this.applied] = rectOf(this.resolve(c.doc, nx.target))
    }
  }
}

async function settle(f: HTMLIFrameElement, ms: number) {
  const doc = () => f.contentDocument!
  for (let i = 0; i < 100; i++) {
    const root = doc()?.getElementById('root')
    if (root && root.children.length && (root.textContent?.length ?? 0) > 20) break
    await sleep(100)
  }
  try {
    await (doc() as any).fonts?.ready
  } catch {}
  await sleep(Math.min(ms, 900))
  // Wait for a quiescent layout: text, element count, scroll extents and
  // scroll offsets unchanged for ~1.6s. Under render load the app needs longer
  // for its timer-driven work (scroll-to-latest, panel layout); freezing before
  // that finishes would make frames depend on which worker loaded them.
  const sig = () => {
    const d = doc()
    if (!d?.body) return ''
    let sc = 0
    let st = 0
    for (const e of d.querySelectorAll<HTMLElement>('*')) {
      if (e.scrollHeight > e.clientHeight + 20 && e.clientHeight > 50) {
        sc += e.scrollHeight
        st += e.scrollTop
      }
    }
    return `${d.body.innerText.length}|${d.getElementsByTagName('*').length}|${sc}|${Math.round(st)}`
  }
  let last = ''
  let stable = 0
  for (let i = 0; i < 120 && stable < 6; i++) {
    const g = sig()
    stable = g === last ? stable + 1 : 0
    last = g
    await sleep(150)
  }
  // walk the main scrollers so lazily-attached media get a chance to load
  await waitImages(doc(), 4000)
}

/** short quiescence wait: page text + element count stable for n polls */
async function quiet(doc: Document, n: number, ms: number) {
  let last = ''
  let stable = 0
  for (let i = 0; i < 40 && stable < n; i++) {
    const g = `${doc.body?.innerText.length}|${doc.getElementsByTagName('*').length}`
    stable = g === last ? stable + 1 : 0
    last = g
    await sleep(ms)
  }
}

async function waitImages(doc: Document, timeout: number) {
  const t0 = performance.now()
  while (performance.now() - t0 < timeout) {
    const imgs = [...doc.images].filter((im) => {
      const r = im.getBoundingClientRect()
      return r.width > 0 && r.bottom > 0 && r.top < (doc.defaultView?.innerHeight ?? 2000)
    })
    if (imgs.every((im) => im.complete)) break
    await sleep(100)
  }
  const imgs = [...doc.images].filter((im) => im.complete && im.naturalWidth)
  await Promise.all(imgs.slice(0, 60).map((im) => im.decode().catch(() => {})))
}

let keepMounted = false
/** realtime playback: once loaded, frames stay mounted (no load hitches mid-play) */
export const setKeepMounted = (v: boolean) => (keepMounted = v)

/** synchronous per-frame hooks for realtime playback (async work is fire-and-forget) */
export function runSeekHooksSync(t: number) {
  for (const f of registry) if (f.ready && f.wanted(t) && f.o.onSeek) void f.o.onSeek(f.ctx(), t)
}

export async function syncFrames(t: number) {
  const want = registry.filter((f) => f.wanted(t))
  if (!keepMounted) for (const f of registry) if (!f.wanted(t)) f.unmount()
  // load in small batches to keep memory spikes sane
  for (let i = 0; i < want.length; i += 4) await Promise.all(want.slice(i, i + 4).map((f) => f.mount()))
  for (const f of want) if (f.ready) await f.advance(t)
  for (const f of want) if (f.ready && f.o.onSeek) await f.o.onSeek(f.ctx(), t)
}

export const allFrames = () => registry

// ---------------------------------------------------------------------------
// Window chrome around a frame

export interface Place {
  x: number
  y: number
  s?: number
  rx?: number
  ry?: number
  rz?: number
  z?: number
  o?: number
  blur?: number
  bright?: number
}

export interface WinOpts extends Omit<FrameOpts, 'w' | 'h'> {
  w?: number
  h?: number
  /** css px of the page per stage px (render scale of the page inside the window) */
  k?: number
  kind?: 'mac' | 'browser'
  title?: string
  url?: string
}

const CHROME_H = 40

export class AppWindow {
  el: HTMLElement
  body: HTMLElement
  inner: HTMLElement
  ovl: HTMLElement
  frame: Frame
  W: number
  H: number
  k: number
  constructor(parent: HTMLElement, o: WinOpts) {
    const w = o.w ?? 1280
    const h = o.h ?? 800
    this.k = o.k ?? 0.9
    const theme = o.theme ?? 'dark'
    this.W = Math.round(w * this.k)
    this.H = Math.round(h * this.k) + CHROME_H
    const lights = [div('tl r'), div('tl y'), div('tl g')]
    const chrome = div('chrome', ...lights)
    if (o.kind === 'browser') {
      chrome.append(el('div', { class: 'url' }, icon('lock', 13, 2.4), o.url ?? 'lupyd.com'))
    } else {
      chrome.append(el('div', { class: 'title' }, o.title ?? 'Lupyd'))
    }
    this.inner = el('div', { class: 'inner', style: `width:${w}px;height:${h}px;transform:scale(${this.k})` })
    this.inner.append(el('div', { class: 'placeholder' }))
    this.ovl = el('div', { class: 'ovl', style: `width:${w}px;height:${h}px` })
    this.body = el('div', { class: 'body', style: `width:${this.W}px;height:${this.H - CHROME_H}px` }, this.inner)
    this.inner.append(this.ovl)
    this.el = el('div', { class: `win ${theme}`, style: `width:${this.W}px;height:${this.H}px` }, chrome, this.body)
    parent.append(this.el)
    this.frame = new Frame(this.inner, { ...o, w, h })
  }
  place(p: Place) {
    const s = p.s ?? 1
    const o = p.o ?? 1
    css(this.el, {
      transform: `translate3d(${(p.x - this.W / 2).toFixed(2)}px, ${(p.y - this.H / 2).toFixed(2)}px, ${(p.z ?? 0).toFixed(2)}px) rotateX(${(p.rx ?? 0).toFixed(3)}deg) rotateY(${(p.ry ?? 0).toFixed(3)}deg) rotateZ(${(p.rz ?? 0).toFixed(3)}deg) scale(${s.toFixed(4)})`,
      opacity: o.toFixed(3),
      filter: (p.blur ?? 0) > 0.05 || (p.bright ?? 1) !== 1 ? `blur(${(p.blur ?? 0).toFixed(2)}px) brightness(${(p.bright ?? 1).toFixed(3)})` : 'none',
      // never visibility:hidden: pages must load in the same (visible) state on every worker
    })
  }
  /** page css px → stage px, valid when the window is unrotated */
  toStage(p: Place, px: number, py: number) {
    const s = p.s ?? 1
    return { x: p.x + (-this.W / 2 + px * this.k) * s, y: p.y + (-this.H / 2 + CHROME_H + py * this.k) * s }
  }
}

export interface PhoneOpts extends Omit<FrameOpts, 'w' | 'h'> {
  k?: number
  native?: boolean
}

/** parse "rgb(a)" → [r,g,b,a] */
const parseRgb = (c: string) => {
  const m = c.match(/rgba?\(([^)]+)\)/)
  if (!m) return null
  const v = m[1].split(/[ ,/]+/).filter(Boolean).map(Number)
  return [v[0], v[1], v[2], v[3] ?? 1]
}
/** opaque colour the user sees at a page point (alpha-composited down the tree) */
function paintedColor(doc: Document, x: number, y: number, fallback: string) {
  let e = doc.elementFromPoint(x, y) as HTMLElement | null
  const layers: number[][] = []
  while (e) {
    const c = parseRgb(getComputedStyle(e).backgroundColor)
    if (c && c[3] > 0) {
      layers.push(c)
      if (c[3] >= 0.999) break
    }
    e = e.parentElement
  }
  let out = parseRgb(fallback) ?? [0, 0, 0, 1]
  for (let i = layers.length - 1; i >= 0; i--) {
    const [r, g, b, a] = layers[i]
    out = [out[0] * (1 - a) + r * a, out[1] * (1 - a) + g * a, out[2] * (1 - a) + b * a, 1]
  }
  return `rgb(${out.slice(0, 3).map((v) => Math.round(v)).join(',')})`
}

/**
 * iPhone-like device. The app fills the whole screen edge to edge: the status
 * bar and the home-indicator strip are painted with the colours the app shows
 * at its top and bottom edges (sampled after load), so there is no seam,
 * letterbox or frame-inside-a-frame.
 */
export class Phone {
  el: HTMLElement
  screen: HTMLElement
  inner: HTMLElement
  ovl: HTMLElement
  frame: Frame | null = null
  W: number
  H: number
  k: number
  static SW = 390
  static SH = 844
  static STATUS = 50
  static HOME = 22
  statusBar: HTMLElement
  homeBar: HTMLElement
  constructor(parent: HTMLElement, o: PhoneOpts) {
    this.k = o.k ?? 0.8
    const theme = o.theme ?? 'dark'
    const bg = theme === 'dark' ? 'rgb(3,7,17)' : 'rgb(255,255,255)'
    const sw = Phone.SW * this.k
    const sh = Phone.SH * this.k
    this.W = sw + 26
    this.H = sh + 26
    this.inner = el('div', { class: 'inner', style: `position:absolute;left:0;top:0;width:${Phone.SW}px;height:${Phone.SH}px;transform:scale(${this.k});transform-origin:0 0;background:${bg}` })
    this.statusBar = el('div', { style: `position:absolute;left:0;top:0;width:${Phone.SW}px;height:${Phone.STATUS}px;background:${bg}` })
    this.homeBar = el('div', { style: `position:absolute;left:0;bottom:0;width:${Phone.SW}px;height:${Phone.HOME}px;background:${bg}` })
    const status = el('div', { class: `status ${theme === 'light' ? 'light-status' : ''}` }, '9:41', el('span', { style: 'display:flex;gap:6px;align-items:center' }, signalSvg(), batterySvg()))
    const pageH = Phone.SH - Phone.STATUS - Phone.HOME
    const pageHost = el('div', { style: `position:absolute;left:0;top:${Phone.STATUS}px;width:${Phone.SW}px;height:${pageH}px;overflow:hidden` })
    this.ovl = el('div', { class: 'ovl', style: `position:absolute;left:0;top:0;width:${Phone.SW}px;height:${Phone.SH}px;pointer-events:none` })
    const home = el('div', { style: `position:absolute;left:50%;bottom:7px;width:134px;height:5px;margin-left:-67px;border-radius:3px;background:${theme === 'dark' ? 'rgba(255,255,255,0.8)' : 'rgba(0,0,0,0.8)'};z-index:6` })
    this.inner.append(this.statusBar, this.homeBar, pageHost, status, el('div', { class: 'island' }), this.ovl, home)
    this.screen = el('div', { class: 'screen', style: `width:${sw}px;height:${sh}px;background:${bg}` }, this.inner)
    this.el = el('div', { class: 'phone', style: `width:${this.W}px;height:${this.H}px` }, this.screen)
    parent.append(this.el)
    if (!o.native) {
      const userPrepare = o.prepare
      this.frame = new Frame(pageHost, {
        ...o,
        w: Phone.SW,
        h: pageH,
        prepare: async (c) => {
          if (userPrepare) await userPrepare(c)
          this.paintEdges(c.doc, bg)
        },
      })
    } else this.native = pageHost
  }
  /** match the status bar / home strip to the app's own top and bottom edge */
  paintEdges(doc: Document, bg: string) {
    const h = doc.defaultView!.innerHeight
    css(this.statusBar, { background: paintedColor(doc, Phone.SW / 2, 1, bg) })
    css(this.homeBar, { background: paintedColor(doc, Phone.SW / 2, h - 2, bg) })
  }
  native: HTMLElement | null = null
  place(p: Place) {
    const s = p.s ?? 1
    const o = p.o ?? 1
    css(this.el, {
      transform: `translate3d(${(p.x - this.W / 2).toFixed(2)}px, ${(p.y - this.H / 2).toFixed(2)}px, ${(p.z ?? 0).toFixed(2)}px) rotateX(${(p.rx ?? 0).toFixed(3)}deg) rotateY(${(p.ry ?? 0).toFixed(3)}deg) rotateZ(${(p.rz ?? 0).toFixed(3)}deg) scale(${s.toFixed(4)})`,
      opacity: o.toFixed(3),
      filter: (p.blur ?? 0) > 0.05 ? `blur(${(p.blur ?? 0).toFixed(2)}px)` : 'none',
    })
  }
  /** app page css px (inside the iframe) → stage px, valid when unrotated */
  toStage(p: Place, px: number, py: number) {
    const s = p.s ?? 1
    return { x: p.x + (-this.W / 2 + 13 + px * this.k) * s, y: p.y + (-this.H / 2 + 13 + (py + (this.frame ? Phone.STATUS : 0)) * this.k) * s }
  }
}

function signalSvg() {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  s.setAttribute('width', '18')
  s.setAttribute('height', '12')
  s.setAttribute('viewBox', '0 0 18 12')
  s.innerHTML = '<rect x="0" y="8" width="3" height="4" rx="1" fill="currentColor"/><rect x="5" y="5.5" width="3" height="6.5" rx="1" fill="currentColor"/><rect x="10" y="3" width="3" height="9" rx="1" fill="currentColor"/><rect x="15" y="0" width="3" height="12" rx="1" fill="currentColor"/>'
  return s
}
function batterySvg() {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  s.setAttribute('width', '27')
  s.setAttribute('height', '13')
  s.setAttribute('viewBox', '0 0 27 13')
  s.innerHTML = '<rect x="0.5" y="0.5" width="23" height="12" rx="3.5" fill="none" stroke="currentColor" opacity="0.4"/><rect x="2" y="2" width="17" height="9" rx="2" fill="currentColor"/><path d="M25 4.5v4c.8-.3 1.5-1.1 1.5-2s-.7-1.7-1.5-2z" fill="currentColor" opacity="0.4"/>'
  return s
}
