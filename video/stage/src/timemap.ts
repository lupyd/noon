// Speed ramps over a recorded beat (timeline shot `speed`: [[clip t, rate], …],
// each rate holding until the next breakpoint). Stage time ↔ clip time.
export type Speed = [number, number][] | undefined

/** clip time reached `st` stage-seconds after the clip starts at clip time `a` */
export function clipAt(speed: Speed, a: number, st: number) {
  if (!speed) return a + st
  let t = a
  let left = Math.max(0, st)
  for (let i = 0; i < speed.length; i++) {
    const end = speed[i + 1]?.[0] ?? Infinity
    if (end <= t) continue
    const span = (end - t) / speed[i][1]
    if (left <= span) return t + left * speed[i][1]
    left -= span
    t = end
  }
  return t
}

/** stage seconds after the clip start at which clip time `ct` plays */
export function stageAt(speed: Speed, a: number, ct: number) {
  if (!speed) return ct - a
  let d = 0
  for (let i = 0; i < speed.length; i++) {
    const lo = Math.max(a, speed[i][0])
    const hi = Math.min(ct, speed[i + 1]?.[0] ?? Infinity)
    if (hi > lo) d += (hi - lo) / speed[i][1]
  }
  return d
}
