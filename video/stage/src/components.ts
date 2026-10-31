import { css, div, el, icon, LOGO_PATH, LOGO_TRANSFORM, svgNS } from './dom'
import { clamp, ease, env, hash, lerp, mulberry32, prog, spring, springs, SpringOpts } from './motion'

// ---------------------------------------------------------------------------
// Kinetic type: per-character spring rise with blur → sharp

export interface KineticOpts {
  size?: number
  weight?: number
  serif?: boolean
  color?: string
  x?: number
  y?: number
  align?: 'center' | 'left' | 'right'
  tracking?: number
  glow?: boolean
}

export class Kinetic {
  el: HTMLElement
  chars: HTMLElement[] = []
  constructor(parent: HTMLElement, public text: string, public o: KineticOpts = {}) {
    const size = o.size ?? 120
    this.el = el('div', {
      class: `kin ${o.serif ? 'serif' : ''}`,
      style: `font-size:${size}px;${o.weight ? `font-weight:${o.weight};` : ''}${o.color ? `color:${o.color};` : ''}${o.tracking !== undefined ? `letter-spacing:${o.tracking}em;` : ''}${o.glow ? 'text-shadow:0 0 40px rgba(200,210,255,0.35), 0 0 120px rgba(160,180,255,0.25);' : ''}`,
    })
    for (const word of text.split(/(\s+)/)) {
      const w = el('span', { class: 'w' })
      for (const ch of word) {
        const c = el('span', { class: 'c' }, ch)
        this.chars.push(c)
        w.append(c)
      }
      this.el.append(w)
    }
    parent.append(this.el)
  }
  /**
   * t: local seconds, inAt: reveal start, outAt: exit start (optional).
   * `pos` lets the caller move/scale the whole line.
   */
  update(
    t: number,
    inAt: number,
    outAt = Infinity,
    pos: { x?: number; y?: number; s?: number; o?: number; blur?: number } = {},
    opts: { stagger?: number; rise?: number; blur?: number; sp?: SpringOpts; outStagger?: number; outDur?: number } = {}
  ) {
    const stagger = opts.stagger ?? 0.028
    const rise = opts.rise ?? 0.42
    const bl = opts.blur ?? 14
    const sp = opts.sp ?? springs.soft
    const outStagger = opts.outStagger ?? 0.012
    const outDur = opts.outDur ?? 0.45
    const x = pos.x ?? this.o.x ?? 960
    const y = pos.y ?? this.o.y ?? 540
    const s = pos.s ?? 1
    const align = this.o.align ?? 'center'
    const tx = align === 'center' ? '-50%' : align === 'right' ? '-100%' : '0%'
    const visible = t >= inAt - 0.01 && t <= outAt + outDur + this.chars.length * outStagger + 0.05
    css(this.el, {
      transform: `translate(${x}px, ${y}px) translate(${tx}, -50%) scale(${s})`,
      transformOrigin: align === 'left' ? '0% 50%' : align === 'right' ? '100% 50%' : '50% 50%',
      opacity: String(pos.o ?? 1),
      filter: (pos.blur ?? 0) > 0.05 ? `blur(${pos.blur}px)` : 'none',
      visibility: visible ? 'visible' : 'hidden',
    })
    if (!visible) return
    const size = this.o.size ?? 120
    const n = this.chars.length
    for (let i = 0; i < n; i++) {
      const p = spring(t - inAt - i * stagger, sp)
      const q = ease.inCubic(prog(t, outAt + i * outStagger, outAt + i * outStagger + outDur))
      const a = clamp(p * 1.6) * (1 - q)
      const dy = (1 - p) * rise * size - q * 0.35 * size
      const b = (1 - clamp(p * 1.25)) * bl + q * bl
      css(this.chars[i], {
        transform: `translate3d(0, ${dy.toFixed(2)}px, 0)`,
        opacity: a.toFixed(3),
        filter: b > 0.1 ? `blur(${b.toFixed(2)}px)` : 'none',
      })
    }
  }
}

// ---------------------------------------------------------------------------
// Pills / callouts

export class Pill {
  el: HTMLElement
  constructor(parent: HTMLElement, iconName: string, text: string, variant = '', sub?: string) {
    this.el = el('div', { class: `pill ${variant}` }, el('span', { class: 'ico' }, icon(iconName, 17, 2.2)), el('span', {}, text), sub ? el('small', {}, sub) : null)
    parent.append(this.el)
  }
  /** pop in at `at`, out at `outAt`; x/y = left-middle anchor unless anchor = 'center' */
  update(t: number, at: number, outAt: number, x: number, y: number, anchor: 'left' | 'center' | 'right' = 'left') {
    const p = spring(t - at, springs.pop)
    const q = ease.inCubic(prog(t, outAt, outAt + 0.3))
    const a = clamp(p * 2) * (1 - q)
    const tx = anchor === 'center' ? '-50%' : anchor === 'right' ? '-100%' : '0%'
    css(this.el, {
      transform: `translate(${x.toFixed(1)}px, ${y.toFixed(1)}px) translate(${tx}, -50%) translateY(${((1 - p) * 14 - q * 8).toFixed(2)}px) scale(${(0.82 + 0.18 * p - q * 0.06).toFixed(4)})`,
      transformOrigin: anchor === 'center' ? '50% 50%' : anchor === 'right' ? '100% 50%' : '0% 50%',
      opacity: a.toFixed(3),
      visibility: a > 0.001 ? 'visible' : 'hidden',
    })
  }
}

// ---------------------------------------------------------------------------
// Cursor with eased path + click ripples

export interface CursorKey {
  t: number
  x: number
  y: number
  click?: boolean
}
export class Cursor {
  el: HTMLElement
  ripple: HTMLElement
  constructor(parent: HTMLElement) {
    this.el = el('div', {
      class: 'cursor',
      html: `<svg width="30" height="30" viewBox="0 0 28 28"><path d="M5.5 3.2v19.6c0 .6.7.9 1.1.5l4.6-4.6 3.2 7.2c.2.4.6.6 1 .4l2.6-1.1c.4-.2.6-.6.4-1l-3.2-7.1h6.4c.6 0 .9-.7.5-1.1L6.6 2.7c-.4-.4-1.1-.1-1.1.5z" fill="#111" stroke="#fff" stroke-width="1.6" stroke-linejoin="round"/></svg>`,
    })
    this.ripple = el('div', { class: 'ripple' })
    parent.append(this.ripple, this.el)
  }
  update(t: number, path: CursorKey[], visible: [number, number]) {
    const a = env(t, visible[0], visible[1], 0.25, 0.3)
    let x = path[0].x
    let y = path[0].y
    for (let i = 1; i < path.length; i++) {
      const k0 = path[i - 1]
      const k1 = path[i]
      if (t >= k0.t) {
        const p = ease.inOutCubic(prog(t, k0.t, k1.t))
        // slight arc for a hand-moved feel
        const arc = Math.sin(p * Math.PI) * Math.min(60, Math.hypot(k1.x - k0.x, k1.y - k0.y) * 0.12)
        x = lerp(k0.x, k1.x, p)
        y = lerp(k0.y, k1.y, p) - arc
      }
    }
    // click: find most recent click key
    let press = 0
    let rip = -1
    for (const k of path) {
      if (!k.click) continue
      const d = t - k.t
      if (d >= -0.08 && d < 0.16) press = Math.max(press, 1 - Math.abs(d - 0.04) / 0.12)
      if (d >= 0 && d < 0.6) rip = d
    }
    css(this.el, {
      transform: `translate(${(x - 6).toFixed(1)}px, ${(y - 3).toFixed(1)}px) scale(${(1 - 0.14 * clamp(press)).toFixed(3)})`,
      opacity: a.toFixed(3),
      visibility: a > 0.001 ? 'visible' : 'hidden',
    })
    if (rip >= 0) {
      const p = ease.outCubic(rip / 0.6)
      css(this.ripple, { transform: `translate(${x}px, ${y}px) scale(${(0.3 + p * 1.3).toFixed(3)})`, opacity: ((1 - p) * 0.9 * a).toFixed(3), visibility: 'visible' })
    } else css(this.ripple, { visibility: 'hidden' })
    return { x, y }
  }
}

// ---------------------------------------------------------------------------
// Ciphertext scramble

const GLYPHS = 'ABCDEF0123456789abcdef+/=#%&$@*'
export function scramble(text: string, t: number, revealFrom: number, revealTo: number, seed = 1, rate = 22) {
  // chars resolve left → right between revealFrom and revealTo; before: all cipher
  const n = text.length
  const frame = Math.floor(t * rate)
  let out = ''
  for (let i = 0; i < n; i++) {
    const ch = text[i]
    const at = lerp(revealFrom, revealTo, n <= 1 ? 0 : i / (n - 1))
    if (ch === ' ' && t >= at) {
      out += ' '
      continue
    }
    if (t >= at) out += ch
    else out += GLYPHS[Math.floor(hash(i * 13.1 + frame * 7.7 + seed) * GLYPHS.length)]
  }
  return out
}
/** forward: plaintext → cipher between a and b */
export function encrypt(text: string, t: number, a: number, b: number, seed = 1) {
  const n = text.length
  const frame = Math.floor(t * 22)
  let out = ''
  for (let i = 0; i < n; i++) {
    const at = lerp(a, b, n <= 1 ? 0 : i / (n - 1))
    if (t < at) out += text[i]
    else out += GLYPHS[Math.floor(hash(i * 13.1 + frame * 7.7 + seed) * GLYPHS.length)]
  }
  return out
}
export function hexNoise(t: number, seed: number, groups = 6, rate = 14) {
  const f = Math.floor(t * rate)
  const r = mulberry32(seed * 9973 + f * 31)
  const parts = []
  for (let g = 0; g < groups; g++) parts.push(Math.floor(r() * 65536).toString(16).padStart(4, '0'))
  return '0x' + parts.join(' ')
}

// ---------------------------------------------------------------------------
// Logo

export function logoMark(size: number, invert = false) {
  const s = document.createElementNS(svgNS, 'svg')
  s.setAttribute('viewBox', '0 0 800 800')
  s.setAttribute('width', String(size))
  s.setAttribute('height', String(size))
  s.innerHTML = `<circle cx="400" cy="400" r="400" fill="${invert ? '#000' : '#fff'}"/><g transform="${LOGO_TRANSFORM}"><path fill="${invert ? '#fff' : '#000'}" d="${LOGO_PATH}"/></g>`
  return s
}

// ---------------------------------------------------------------------------
// Shatter: clone an element into jittered triangular shards

export class Shatter {
  shards: { el: HTMLElement; cx: number; cy: number; vx: number; vy: number; vr: number; rx: number; ry: number; delay: number }[] = []
  built = false
  constructor(public src: HTMLElement, public seed: number) {}
  build() {
    if (this.built) return
    const w = this.src.offsetWidth
    const h = this.src.offsetHeight
    if (!w) return
    const parent = this.src.parentElement!
    const r = mulberry32(this.seed)
    const cols = 4
    const rows = 2
    const pts: number[][][] = []
    for (let j = 0; j <= rows; j++) {
      pts.push([])
      for (let i = 0; i <= cols; i++) {
        const edgeX = i === 0 || i === cols
        const edgeY = j === 0 || j === rows
        pts[j].push([(i / cols) * w + (edgeX ? 0 : (r() - 0.5) * (w / cols) * 0.7), (j / rows) * h + (edgeY ? 0 : (r() - 0.5) * (h / rows) * 0.6)])
      }
    }
    const tris: number[][][] = []
    for (let j = 0; j < rows; j++)
      for (let i = 0; i < cols; i++) {
        const a = pts[j][i], b = pts[j][i + 1], c = pts[j + 1][i + 1], d = pts[j + 1][i]
        if (r() > 0.5) tris.push([a, b, c], [a, c, d])
        else tris.push([a, b, d], [b, c, d])
      }
    for (const tri of tris) {
      const clone = this.src.cloneNode(true) as HTMLElement
      clone.style.clipPath = `polygon(${tri.map(([x, y]) => `${x.toFixed(1)}px ${y.toFixed(1)}px`).join(',')})`
      clone.style.visibility = 'hidden'
      parent.append(clone)
      const cx = (tri[0][0] + tri[1][0] + tri[2][0]) / 3
      const cy = (tri[0][1] + tri[1][1] + tri[2][1]) / 3
      const dx = cx - w / 2
      const dy = cy - h / 2
      const len = Math.hypot(dx, dy) || 1
      const sp = 260 + r() * 420
      this.shards.push({ el: clone, cx, cy, vx: (dx / len) * sp + (r() - 0.5) * 160, vy: (dy / len) * sp * 0.7 - 120 - r() * 160, vr: (r() - 0.5) * 540, rx: (r() - 0.5) * 220, ry: (r() - 0.5) * 220, delay: r() * 0.08 })
    }
    this.built = true
  }
  /** returns whether shards are active (caller hides the source) */
  update(t: number, at: number, baseTransform: string) {
    this.build()
    const active = t >= at
    for (const s of this.shards) {
      const d = Math.max(0, t - at - s.delay)
      const a = active ? clamp(1 - d / 1.1) : 0
      const x = s.vx * d
      const y = s.vy * d + 520 * d * d
      css(s.el, {
        transform: `${baseTransform} translate3d(${x.toFixed(1)}px, ${y.toFixed(1)}px, ${(d * 160).toFixed(1)}px) rotateX(${(s.rx * d).toFixed(1)}deg) rotateY(${(s.ry * d).toFixed(1)}deg) rotateZ(${(s.vr * d).toFixed(1)}deg)`,
        transformOrigin: `${s.cx}px ${s.cy}px`,
        opacity: a.toFixed(3),
        visibility: a > 0.001 ? 'visible' : 'hidden',
      })
    }
    return active
  }
}

export const avatar = (name: string) => `/media/avatar-${name}.webp`

export { div, el, icon }
