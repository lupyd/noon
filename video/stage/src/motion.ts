// Pure, time-driven motion math. Nothing here reads the clock.
export const clamp = (x: number, a = 0, b = 1) => Math.min(b, Math.max(a, x))
export const lerp = (a: number, b: number, t: number) => a + (b - a) * t
export const prog = (t: number, a: number, b: number) => (b === a ? (t >= b ? 1 : 0) : clamp((t - a) / (b - a)))
export const mix = (a: number, b: number, t: number) => lerp(a, b, clamp(t))

export const ease = {
  linear: (t: number) => t,
  inCubic: (t: number) => t * t * t,
  outCubic: (t: number) => 1 - Math.pow(1 - t, 3),
  inOutCubic: (t: number) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2),
  outQuart: (t: number) => 1 - Math.pow(1 - t, 4),
  inOutQuart: (t: number) => (t < 0.5 ? 8 * t ** 4 : 1 - Math.pow(-2 * t + 2, 4) / 2),
  outExpo: (t: number) => (t >= 1 ? 1 : 1 - Math.pow(2, -10 * t)),
  inExpo: (t: number) => (t <= 0 ? 0 : Math.pow(2, 10 * t - 10)),
  inOutExpo: (t: number) =>
    t <= 0 ? 0 : t >= 1 ? 1 : t < 0.5 ? Math.pow(2, 20 * t - 10) / 2 : (2 - Math.pow(2, -20 * t + 10)) / 2,
  outBack: (t: number, s = 1.70158) => 1 + (s + 1) * Math.pow(t - 1, 3) + s * Math.pow(t - 1, 2),
  inOutSine: (t: number) => -(Math.cos(Math.PI * t) - 1) / 2,
}

/** eased progress between a and b */
export const ep = (t: number, a: number, b: number, fn: (x: number) => number = ease.inOutCubic) => fn(prog(t, a, b))

export interface SpringOpts {
  stiffness?: number
  damping?: number
  mass?: number
}
/** Analytic damped spring from 0 → 1, `t` seconds after release (0 for t<=0). */
export function spring(t: number, { stiffness = 170, damping = 22, mass = 1 }: SpringOpts = {}) {
  if (t <= 0) return 0
  const w0 = Math.sqrt(stiffness / mass)
  const zeta = damping / (2 * Math.sqrt(stiffness * mass))
  if (zeta < 1) {
    const wd = w0 * Math.sqrt(1 - zeta * zeta)
    return 1 - Math.exp(-zeta * w0 * t) * (Math.cos(wd * t) + ((zeta * w0) / wd) * Math.sin(wd * t))
  }
  // critically / over-damped
  return 1 - Math.exp(-w0 * t) * (1 + w0 * t)
}
export const springs = {
  pop: { stiffness: 260, damping: 18 },
  soft: { stiffness: 120, damping: 20 },
  snappy: { stiffness: 320, damping: 30 },
  gentle: { stiffness: 80, damping: 18 },
  heavy: { stiffness: 90, damping: 22, mass: 1.6 },
}

/** in/out envelope: 0 before a, ramps to 1 over fadeIn, stays, ramps down to 0 ending at b */
export function env(t: number, a: number, b: number, fadeIn = 0.4, fadeOut = 0.4, fn = ease.inOutCubic) {
  return fn(prog(t, a, a + fadeIn)) * (1 - fn(prog(t, b - fadeOut, b)))
}

// Deterministic PRNG
export function mulberry32(seed: number) {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}
export const hash = (n: number) => {
  let x = Math.sin(n * 127.1 + 311.7) * 43758.5453
  return x - Math.floor(x)
}
/** smooth 1D value noise in [-1, 1] */
export function noise1(x: number, seed = 0) {
  const i = Math.floor(x)
  const f = x - i
  const u = f * f * (3 - 2 * f)
  return lerp(hash(i + seed * 57.3), hash(i + 1 + seed * 57.3), u) * 2 - 1
}

/** piecewise keyframes: [[t, value], ...] with easing between */
export function keys(t: number, frames: [number, number][], fn = ease.inOutCubic) {
  if (t <= frames[0][0]) return frames[0][1]
  for (let i = 1; i < frames.length; i++) {
    const [t1, v1] = frames[i]
    const [t0, v0] = frames[i - 1]
    if (t <= t1) return lerp(v0, v1, fn(prog(t, t0, t1)))
  }
  return frames[frames.length - 1][1]
}
