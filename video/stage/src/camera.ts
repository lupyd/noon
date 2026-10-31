// Virtual camera. Each scene puts its content in a `.world` layer; the camera
// frames a focus point (stage px) at a zoom, and moves between keyframes with
// cubic easing (zoom interpolated in log space so push-ins feel linear to the
// eye). Everything is a pure function of t.
import { css } from './dom'
import { ease, lerp, noise1, prog } from './motion'

export interface CamKey {
  t: number
  x: number
  y: number
  z: number
  /** easing for the segment that ENDS at this key */
  ease?: (x: number) => number
}

export interface CamState {
  x: number
  y: number
  z: number
}

export const WIDE: Omit<CamKey, 't'> = { x: 960, y: 540, z: 1 }

export function camAt(t: number, keys: CamKey[]): CamState {
  if (!keys.length) return { ...WIDE }
  if (t <= keys[0].t) return { x: keys[0].x, y: keys[0].y, z: keys[0].z }
  for (let i = 1; i < keys.length; i++) {
    const a = keys[i - 1]
    const b = keys[i]
    if (t <= b.t) {
      const p = (b.ease ?? ease.inOutCubic)(prog(t, a.t, b.t))
      const z = Math.exp(lerp(Math.log(a.z), Math.log(b.z), p))
      // keep the focus path stable while zooming: blend in screen space
      return { x: lerp(a.x, b.x, p), y: lerp(a.y, b.y, p), z }
    }
  }
  const l = keys[keys.length - 1]
  return { x: l.x, y: l.y, z: l.z }
}

export class Camera {
  state: CamState = { ...WIDE }
  constructor(public world: HTMLElement, public drift = 1) {}
  /** apply the camera for local time t; returns the state used */
  /**
   * bounds: keep the view inside this world rect (+margin) — a push-in never
   * shows empty backdrop beside the UI it is featuring. amt blends it in/out.
   */
  apply(t: number, keys: CamKey[], seed = 0, bounds?: { x: number; y: number; w: number; h: number } | null, amt = 1, margin = 50) {
    const s = camAt(t, keys)
    if (bounds && amt > 0) {
      const fit = (c: number, lo: number, size: number, half: number) => {
        const a = lo + half - margin
        const b = lo + size - half + margin
        return a > b ? lo + size / 2 : Math.min(b, Math.max(a, c))
      }
      s.x = lerp(s.x, fit(s.x, bounds.x, bounds.w, 960 / s.z), amt)
      s.y = lerp(s.y, fit(s.y, bounds.y, bounds.h, 540 / s.z), amt)
    }
    // a hint of handheld float, scaled down when pushed in so text stays steady
    const d = this.drift / Math.max(1, s.z)
    s.x += noise1(t * 0.23, 11 + seed) * 6 * d
    s.y += noise1(t * 0.19, 17 + seed) * 4 * d
    this.state = s
    css(this.world, { transform: `translate(960px, 540px) scale(${s.z.toFixed(5)}) translate(${(-s.x).toFixed(2)}px, ${(-s.y).toFixed(2)}px)` })
    return s
  }
  /** world point → screen point under the current camera */
  toScreen(p: { x: number; y: number }) {
    const s = this.state
    return { x: 960 + (p.x - s.x) * s.z, y: 540 + (p.y - s.y) * s.z }
  }
}

/** focus a world rect so it fills `fill` of the frame (clamped to [zMin, zMax]) */
export function frameRect(r: { x: number; y: number; w: number; h: number }, fill = 0.6, zMax = 2.4, zMin = 1) {
  const z = Math.min(zMax, Math.max(zMin, Math.min((1920 * fill) / r.w, (1080 * fill) / r.h)))
  return { x: r.x + r.w / 2, y: r.y + r.h / 2, z }
}
