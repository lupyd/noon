// v4: launch film. Real app footage (beats/*.mp4, recorded at 2×) staged with
// motion: glass windows with a gloss sweep, 3D entrances/exits cut on the beat,
// confident camera push-ins derived from the logged rects, message bubbles that
// burst out of the app, an encryption journey, and a desktop → phone hand-off.
// Still banned: marketing chips, neon outlines, gradient-text badges.
import { encrypt, hexNoise, scramble } from '../components'
import { css, el, icon } from '../dom'
import { clamp, ease, lerp, spring, springs } from '../motion'
import type { SceneBuilder } from '../types'
import { cue } from '../cues'
import { clipAt, stageAt } from '../timemap'
import { type BeatMeta, type Rect, type View, CURSOR_SVG, FULL, PUSH, easeOutExpoish, focusView, logo, mixView, pointerAt, seekVideo } from './v3'

// ---------------------------------------------------------------- shared
const WIN = { w: 1536, bar: 34 } // the one hero window size, used by every desktop shot
const outExpo = easeOutExpoish
/** draft renders (720p) never need the 2× masters: play display-size proxies only */
const DRAFT = new URLSearchParams(location.search).get('q') === 'draft'
export const srcOf = (b: BeatMeta) => ((b as any).proxy as string) ?? b.src
/** experiment switches from the timeline (EXP=…) */
const exp = (name: string) => ((window as any).__timeline?.exp ?? []).includes(name)
export const ep = (t: number, a: number, b: number, f = outExpo) => f(clamp((t - a) / (b - a)))

interface Place3 { x: number; y: number; z?: number; rx?: number; ry?: number; s?: number; o?: number; blur?: number }
export function place(e: HTMLElement, w: number, h: number, p: Place3) {
  css(e, {
    transform: `translate3d(${(p.x - w / 2).toFixed(2)}px, ${(p.y - h / 2).toFixed(2)}px, ${(p.z ?? 0).toFixed(2)}px) rotateX(${(p.rx ?? 0).toFixed(3)}deg) rotateY(${(p.ry ?? 0).toFixed(3)}deg) scale(${(p.s ?? 1).toFixed(4)})`,
    opacity: (p.o ?? 1).toFixed(3),
    filter: (p.blur ?? 0) > 0.05 ? `blur(${(p.blur ?? 0).toFixed(2)}px)` : 'none',
  })
}

/** glass desktop window holding a recorded clip */
export function glassWindow(parent: HTMLElement, b: BeatMeta, w = WIN.w) {
  const bh = Math.round((w * b.viewport.height) / b.viewport.width)
  const H = bh + WIN.bar
  const win = el('div', { class: 'v4-win', style: `width:${w}px;height:${H}px` })
  const bar = el('div', { class: 'v4-bar' }, el('i', { class: 'r' }), el('i', { class: 'y' }), el('i', { class: 'g' }))
  const video = el('video', { muted: true, playsinline: true, preload: 'auto', src: srcOf(b), style: `width:${w}px;height:${bh}px` }) as HTMLVideoElement
  video.muted = true
  // 2× master, loaded lazily and shown only while the camera is pushed in (1080p tiers)
  const hi = el('video', { muted: true, playsinline: true, preload: 'none', style: `position:absolute;left:0;top:${WIN.bar}px;width:${w}px;height:${bh}px;opacity:0` }) as HTMLVideoElement
  hi.muted = true
  const gloss = el('div', { class: 'v4-gloss' })
  win.append(bar, video, hi, gloss)
  parent.append(win)
  return { win, video, hi, gloss, W: w, H, bh }
}
/** a light band sweeping across the glass (p: 0 → 1) */
export const sweep = (g: HTMLElement, p: number) => css(g, { backgroundPosition: `${(-60 + 220 * p).toFixed(1)}% 0`, opacity: p > 0 && p < 1 ? '1' : '0' })

/**
 * Sequential transitions (v5). A scene only exists inside its own span; the
 * outgoing shot has fully left before the incoming one moves.
 *   enter: 'rise'  — from depth, tilt flattening (0 → 0.45 s after `at`)
 *          'match' — already in place: a match cut on the beat
 *   exit:  'recede' — sinks back and fades into the background (last 0.4 s)
 *          'push'   — the camera carries through it (last 0.35 s)
 *          'match'  — stays put to the cut
 */
export type Enter = 'rise' | 'match'
export type Exit = 'recede' | 'push' | 'match'
export function inOut(lt: number, dur: number, enter: Enter = 'rise', exit: Exit = 'recede', at = 0) {
  const i = enter === 'match' ? 1 : ep(lt, at, at + 0.45)
  const r = exit === 'recede' ? ep(lt, dur - 0.4, dur, ease.inOutCubic) : 0
  const p = exit === 'push' ? ep(lt, dur - 0.35, dur, ease.inCubic) : 0
  const vis = enter === 'match' || lt >= at ? 1 : 0
  return {
    z: (1 - i) * -420 - r * 320 + p * 300,
    rx: (1 - i) * 12,
    s: 1 + p * 0.08,
    o: vis * clamp(i * 1.4) * (1 - r) * (1 - p),
    blur: (1 - i) * 4 + r * 6 + p * 12,
    i,
    out: Math.max(r, p),
  }
}

/** plain, large feature title that opens a scene, then clears before the demo moves in */
export const TITLE = { in: 0.0, out: 0.85, done: 1.05 }
export function titleCard(parent: HTMLElement, text: string | undefined) {
  if (!text) return null
  const e = el('div', { class: 'v4-title' }, text)
  e.style.zIndex = '30'
  parent.append(e)
  return (lt: number) => {
    const p = spring(lt - TITLE.in, { stiffness: 170, damping: 22 })
    const q = ep(lt, TITLE.out, TITLE.done, ease.inCubic)
    css(e, { opacity: (clamp(p * 1.5) * (1 - q)).toFixed(3), transform: `translate(-50%, -50%) translateY(${((1 - p) * 30 - q * 24).toFixed(2)}px)` })
  }
}

// ---------------------------------------------------------------- clip scene
/** one push depth for the whole film */
export const PUSH_Z = 1.9

export const clip: SceneBuilder = ({ root, s, dur }) => {
  const b = (s as any).beat as BeatMeta
  const enter = ((s as any).enter ?? 'rise') as Enter
  const exit = ((s as any).exit ?? 'recede') as Exit
  const title = titleCard(root, (s as any).title)
  const off = title ? TITLE.done - 0.1 : 0 // the demo starts once the title has cleared
  const world = el('div', { class: 'world' })
  world.style.perspective = '2400px'
  root.append(world)
  const g = glassWindow(world, b)
  const body = { x: 960 - g.W / 2, y: 540 - g.H / 2 + WIN.bar, w: g.W, h: g.bh }
  const scale = g.W / b.viewport.width
  const map = (x: number, y: number) => ({ x: body.x + x * scale, y: body.y + y * scale })
  const act = (n?: string) => b.actions.find((a) => a.name === n)
  const S0 = s.start + off
  const sp = (b as any).speed
  const clipT = (lt: number) => clipAt(sp, b.in, Math.max(0, lt - off))
  const at = (ct: number) => S0 + stageAt(sp, b.in, ct)
  // sfx from the log
  for (const a of b.actions) if (a.kind === 'click' && a.t >= b.in && a.t <= b.out) cue(at(a.t), 'click', 0.45)
  for (const a of b.actions) if (a.kind === 'key' && a.t >= b.in && a.t <= b.out) cue(at(a.t), 'pop', 0.45)
  for (const a of b.actions) if (a.kind === 'type' && a.t >= b.in) for (let k = 0; k < ((a as any).text?.length ?? 0); k += 2) cue(at(a.t + (k / ((a as any).text.length)) * ((a.end ?? a.t) - a.t)), 'key', 0.12)
  if (enter === 'rise') cue(S0 - 0.05, 'whoosh', 0.3)

  // the one push-in, onto the logged rect, with a soft light on that element
  let push: { a: number; b: number; view: View; rect: Rect } | null = null
  if (b.focus) {
    const on = act(b.focus.on)
    const until = act(b.focus.until) ?? on
    const rect = on?.rect as Rect | undefined
    if (on && rect) push = { a: on.t - 0.4 - PUSH, b: (until?.end ?? until?.t ?? on.t) + 0.35, view: focusView(rect, map, body, scale, Math.min(PUSH_Z, b.focus.zmax ?? PUSH_Z)), rect }
  }
  const spot = el('div', { class: 'v4-spot' })
  if (push) {
    const r = push.rect
    const c = map(r[0] + r[2] / 2, r[1] + r[3] / 2)
    const d = Math.max(r[2], r[3]) * scale * 2.4
    css(spot, { left: `${(c.x - d / 2).toFixed(1)}px`, top: `${(c.y - d / 2).toFixed(1)}px`, width: `${d.toFixed(1)}px`, height: `${d.toFixed(1)}px` })
    world.append(spot)
  }
  // cursor
  const clicks = b.actions.filter((a) => a.kind === 'click' && a.rect)
  const cursor = el('div', { class: 'v3-cursor', html: CURSOR_SVG })
  const ripple = el('div', { class: 'v3-ripple' })
  if (clicks.length) world.append(ripple, cursor)
  const curOn = clicks.length ? [Math.max(b.in, (b.pointer[0]?.[0] ?? clicks[0].t) - 0.25), clicks[clicks.length - 1].t + 0.6] : [0, -1]
  // channel rows cascade (pixels copied from the clip)
  const pops = (b.pop ?? []).map((n) => act(n)).filter((a): a is NonNullable<typeof a> => !!a?.rect)
  const popEls = pops.map((a) => {
    const r = a.rect as Rect
    const p = map(r[0], r[1])
    const c = el('canvas', { class: 'v3-pop', width: Math.round(r[2] * 2), height: Math.round(r[3] * 2), style: `left:${p.x}px;top:${p.y}px;width:${r[2] * scale}px;height:${r[3] * scale}px` }) as HTMLCanvasElement
    world.append(c)
    return { r, c, ctx: c.getContext('2d')! }
  })
  const popT0 = (act('list')?.t ?? 0) + 0.25
  pops.forEach((_, i) => cue(at(popT0 + i * 0.16), 'tick', 0.3))

  let useHi = false
  return Object.assign(
    (lt: number) => {
      title?.(lt)
      const ct = clipT(lt)
      const io = inOut(lt, dur, enter, exit, title ? TITLE.done : 0)
      // camera: a slow dolly, then the one push-in (same easing family everywhere)
      let v: View = { x: 960, y: 540, z: 1 + 0.02 * clamp((lt - off) / Math.max(1, dur - off)) }
      let pin = 0
      if (push) {
        pin = outExpo(clamp((ct - push.a) / PUSH)) * (1 - outExpo(clamp((ct - push.b) / PUSH)))
        const pIn = outExpo(clamp((ct - push.a) / PUSH))
        const pOut = outExpo(clamp((ct - push.b) / PUSH))
        v = mixView(mixView(v, push.view, pIn), FULL, pOut)
      }
      css(world, { transform: `translate(960px, 540px) scale(${v.z.toFixed(5)}) translate(${(-v.x).toFixed(2)}px, ${(-v.y).toFixed(2)}px)` })
      css(spot, { opacity: (0.9 * pin * io.o).toFixed(3) })
      useHi = !DRAFT && v.z > 1.06
      css(g.hi, { opacity: useHi ? '1' : '0' })
      place(g.win, g.W, g.H, { x: 960, y: 540, z: io.z, rx: io.rx, s: io.s, o: io.o, blur: io.blur })
      sweep(g.gloss, clamp((lt - off + 0.3) / 1.1))
      // cursor
      if (clicks.length) {
        const p = pointerAt(b.pointer, ct)
        const on = lt >= off && ct >= curOn[0] && ct <= curOn[1] && p && io.out < 0.05
        cursor.style.opacity = on ? '1' : '0'
        if (p) {
          const q = map(p.x, p.y)
          const press = clicks.some((c) => ct >= c.t - 0.02 && ct < c.t + 0.12)
          cursor.style.transform = `translate3d(${(q.x - 5).toFixed(1)}px, ${(q.y - 3).toFixed(1)}px, ${io.z.toFixed(1)}px) scale(${press ? 0.88 : 1})`
        }
        const last = [...clicks].reverse().find((c) => ct >= c.t && ct < c.t + 0.55)
        if (last && lt >= off) {
          const r = last.rect as Rect
          const q = map(r[0] + r[2] / 2, r[1] + r[3] / 2)
          const k = (ct - last.t) / 0.55
          ripple.style.transform = `translate3d(${q.x.toFixed(1)}px, ${q.y.toFixed(1)}px, ${io.z.toFixed(1)}px) scale(${(0.35 + 1.1 * k).toFixed(3)})`
          ripple.style.opacity = ((1 - k) * 0.85).toFixed(3)
        } else ripple.style.opacity = '0'
      }
      // rows cascade: lift + settle, one after another
      popEls.forEach(({ r, c, ctx }, i) => {
        const tl = ct - (popT0 + i * 0.16)
        const k = lt >= off && tl > 0 && tl < 0.9 ? spring(tl, { stiffness: 260, damping: 16 }) * (1 - clamp((tl - 0.45) / 0.45)) : 0
        c.style.opacity = k > 0.01 ? '1' : '0'
        c.style.transform = `translateY(${(-4 * k).toFixed(2)}px) scale(${(1 + 0.07 * k).toFixed(4)})`
        c.style.boxShadow = `0 ${(12 * k).toFixed(1)}px ${(30 * k).toFixed(1)}px rgba(0,0,0,${(0.55 * k).toFixed(3)})`
        if (k > 0.01) {
          const sx = (g.video.videoWidth || b.size[0]) / b.viewport.width
          ctx.drawImage(g.video, r[0] * sx, r[1] * sx, r[2] * sx, r[3] * sx, 0, 0, c.width, c.height)
        }
      })
    },
    {
      seek: async (lt: number) => {
        const ct = Math.min(clipT(lt), b.out)
        const pushed = !DRAFT && push && ct > push.a - 0.05 && ct < push.b + PUSH + 0.05
        if (pushed && !g.hi.src) {
          // preload="none" + src never fetches metadata on its own: load it explicitly,
          // otherwise every push-in frame waits out the seek timeout
          g.hi.preload = 'auto'
          g.hi.src = b.src
          g.hi.load()
        }
        await Promise.all([seekVideo(g.video, ct), pushed ? seekVideo(g.hi, ct) : Promise.resolve()])
      },
    }
  )
}

// ---------------------------------------------------------------- E2EE journey
/** the DM window steps left; the sent message locks into noise, crosses the relay, unlocks on the recipient's phone */
export const journey: SceneBuilder = ({ root, s, dur }) => {
  const b = (s as any).beat as BeatMeta
  const msg = (s as any).message as string
  const S0 = s.start
  const world = el('div', { class: 'world' })
  world.style.perspective = '2400px'
  root.append(world)
  const g = glassWindow(world, b) // same 1536 window as the DM shot: a match cut
  const SERVER = { x: 1190, y: 300 }
  const PH = { x: 1560, y: 560, w: 0, h: 0 }
  const T = exp('cinematic-encryption')
    ? { lockA: 1.3, lockB: 2.15, leave: 2.75, atServer: 3.5, leaveServer: 4.3, atPhone: 5.05, decrypt: 5.45 }
    : { lockA: 0.6, lockB: 1.4, leave: 1.7, atServer: 2.6, leaveServer: 3.6, atPhone: 4.5, decrypt: 4.9 }
  cue(S0 + T.lockB - 0.15, 'lock', 0.75)
  cue(S0 + T.leave, 'whoosh', 0.5)
  cue(S0 + T.atServer, 'data', 0.45)
  cue(S0 + T.leaveServer, 'whoosh', 0.45)
  cue(S0 + T.atPhone + 0.1, 'unlock', 0.55)
  // relay
  const server = el('div', { class: 'v4-node', style: `left:${SERVER.x - 58}px;top:${SERVER.y - 58}px` }, icon('server', 48, 1.6))
  const noise = el('div', { class: 'v4-noise', style: `left:${SERVER.x - 120}px;top:${SERVER.y + 80}px;width:240px` })
  const rows = [0, 1, 2].map(() => el('div', {}))
  noise.append(...rows)
  // alex's other device: a real recording of the same thread receiving the message (multi-device sync)
  const sync = (s as any).phone as BeatMeta
  const ph = flagshipPhone(world, sync, 760)
  const arrive = sync.actions.find((a) => a.name === 'arrive')?.t ?? 1.2
  const phone = ph.el
  const inc = el('div', {}) // (real row comes from the recording)
  const lockI = icon('lock', 18, 2.4)
  const unlockI = icon('unlock', 18, 2.4)
  ;[lockI, unlockI].forEach((i) => (i.style.gridArea = '1/1'))
  const pText = el('span', {})
  const packet = el('div', { class: 'v4-packet' }, el('span', { style: 'display:grid' }, lockI, unlockI), pText)
  world.append(server, noise, phone, packet)
  const bez = (a: any, c: any, z: any, p: number) => ({ x: (1 - p) ** 2 * a.x + 2 * (1 - p) * p * c.x + p * p * z.x, y: (1 - p) ** 2 * a.y + 2 * (1 - p) * p * c.y + p * p * z.y })
  return Object.assign(
    (lt: number) => {
      const io = inOut(lt, dur, 'match', 'recede')
      if (!exp('cinematic-encryption')) css(world, { transform: `translate(960px,540px) scale(${(1 + 0.02 * clamp(lt / dur)).toFixed(4)}) translate(-960px,-540px)` })
      const step = ep(lt, 0.15, 1.05)
      const dp = { x: lerp(960, 560, step), y: lerp(540, 560, step), rx: io.rx, ry: lerp(0, 16, step), z: io.z - 160 * step, s: lerp(1, 0.71, step) * io.s, o: io.o, blur: io.blur }
      place(g.win, g.W, g.H, dp)
      const pin = ep(lt, 0.5, 1.4)
      place(phone, ph.W, ph.H, { x: lerp(2150, PH.x, pin), y: PH.y, ry: lerp(-30, -5, pin), rx: 0, z: io.z, o: clamp(pin * 1.5) * io.o })
      const sIn = spring(lt - 0.9, springs.soft)
      css(server, { opacity: (clamp(sIn * 1.5) * io.o).toFixed(3), transform: `scale(${(0.85 + 0.15 * sIn).toFixed(4)})` })
      const atS = clamp((lt - T.atServer + 0.1) / 0.2) * (1 - clamp((lt - T.leaveServer - 0.1) / 0.2))
      css(noise, { opacity: (clamp((lt - T.atServer) / 0.3) * io.o).toFixed(3) })
      rows.forEach((r, i) => (r.textContent = hexNoise(lt + i * 0.37, 11 + i, 4, lt > T.atServer && lt < T.leaveServer + 0.4 ? 14 : 0.0001)))
      // packet path: from the window's last message → relay → phone
      const from = { x: dp.x + 430 * dp.s, y: dp.y + 242 * dp.s }
      const to = { x: PH.x, y: PH.y + 230 }
      let pos = { x: from.x, y: from.y - 60 * ep(lt, T.lockA - 0.1, T.lockA + 0.3) }
      if (lt >= T.leave) pos = bez({ x: from.x, y: from.y - 60 }, { x: (from.x + SERVER.x) / 2, y: SERVER.y - 80 }, SERVER, ep(lt, T.leave, T.atServer, ease.inOutCubic))
      if (lt >= T.atServer) pos = { x: SERVER.x, y: SERVER.y }
      if (lt >= T.leaveServer) pos = bez(SERVER, { x: (SERVER.x + to.x) / 2 + 60, y: SERVER.y - 40 }, to, ep(lt, T.leaveServer, T.atPhone, ease.inOutCubic))
      pText.textContent = lt < T.atPhone ? encrypt(msg, lt, T.lockA, T.lockB, 3) : scramble(msg, lt, T.atPhone + 0.05, T.decrypt - 0.1, 3)
      const locked = lt >= T.lockB - 0.15 && lt < T.atPhone + 0.3
      const lockBeat = spring(lt - (T.lockB - 0.15), { stiffness: 320, damping: 14 })
      const unlockBeat = spring(lt - (T.atPhone + 0.3), { stiffness: 320, damping: 14 })
      css(lockI, { opacity: locked ? '1' : '0', transform: `scale(${(locked ? 0.6 + 0.4 * lockBeat : 1).toFixed(3)})` })
      css(unlockI, { opacity: locked ? '0' : '1', transform: `scale(${(!locked && lt > T.atPhone ? 0.6 + 0.4 * unlockBeat : 1).toFixed(3)})` })
      if (exp('cinematic-encryption')) {
        // camera: push onto the message as it locks into ciphertext, then pull back to follow it out
        const k = ep(lt, T.lockA - 0.5, T.lockA + 0.1) * (1 - ep(lt, T.lockB + 0.1, T.leave + 0.5, ease.inOutCubic))
        const z = 1 + 1.3 * k
        css(world, { transform: `translate(960px,540px) scale(${z.toFixed(4)}) translate(${(-lerp(960, pos.x, k)).toFixed(1)}px,${(-lerp(540, pos.y, k)).toFixed(1)}px)` })
      }
      const pv = clamp((lt - T.lockA + 0.15) / 0.2) * (1 - clamp((lt - T.decrypt) / 0.25))
      const pw = packet.offsetWidth || 360
      css(packet, { transform: `translate(${(pos.x - pw / 2).toFixed(1)}px, ${(pos.y - 24).toFixed(1)}px) scale(${(1 - 0.25 * atS).toFixed(3)})`, opacity: (pv * io.o).toFixed(3), color: locked ? 'var(--mint)' : '#fff' })
      void inc
    },
    { seek: (lt: number) => Promise.all([seekVideo(g.video, b.out), seekVideo(ph.video, Math.max(0, arrive + (lt - T.decrypt) + 0.05))]).then(() => {}) }
  )
}

// ---------------------------------------------------------------- everywhere
/** the desktop window slides back while the phone rises in with a 3D tilt and settles; hold to read */
export const everywhere: SceneBuilder = ({ root, s, dur }) => {
  const desk = (s as any).desk as BeatMeta
  const mob = (s as any).beat as BeatMeta
  const title = titleCard(root, (s as any).title)
  const off = title ? TITLE.done - 0.1 : 0
  const world = el('div', { class: 'world' })
  world.style.perspective = '2200px'
  root.append(world)
  const g = glassWindow(world, desk)
  const ph = flagshipPhone(world, mob, 1080 - 2 * 44) // as large as fits, ≥ 44 px clear top/bottom
  const RISE = off + 0.9
  cue(s.start + RISE, 'whoosh', 0.55)
  return Object.assign(
    (lt: number) => {
      title?.(lt)
      const io = inOut(lt, dur, 'rise', 'recede', title ? TITLE.done : 0)
      const back = ep(lt, RISE - 0.1, RISE + 0.9)
      place(g.win, g.W, g.H, { x: lerp(960, 640, back), y: lerp(540, 520, back), z: io.z - 560 * back, ry: 26 * back, rx: io.rx, o: io.o * (1 - 0.4 * back), blur: io.blur + 3 * back })
      sweep(g.gloss, clamp((lt - off + 0.3) / 1.0))
      const r = ep(lt, RISE, RISE + 1.1)
      const settle = spring(lt - RISE, { stiffness: 70, damping: 14 })
      const po = lt >= RISE ? clamp((lt - RISE) * 4) : 0
      place(ph.el, ph.W, ph.H, { x: lerp(1240, 1260, r), y: lerp(1500, 540, clamp(settle)), z: lerp(-200, 0, r) - 320 * (io.out > 0 ? io.out : 0), rx: lerp(34, 0, clamp(settle)), ry: lerp(-26, -5, r), o: po * (1 - io.out), blur: io.out * 6 })
      sweep(ph.gloss, clamp((lt - RISE - 0.4) / 1.2))
    },
    {
      seek: async (lt: number) => {
        await Promise.all([seekVideo(g.video, desk.in + 2.2), seekVideo(ph.video, mob.in + Math.max(0, lt - RISE))])
      },
    }
  )
}

/**
 * Real Pixel 9 Pro hardware frame (lupyd-about's asset) on top of the screen. Screen = the
 * frame's opening, measured from its alpha: left 10.49%, top 4.53%, width 79.01%, height
 * 91.07%, inner corner radius 193 px of 1280×2856 (15.08% / 6.76%). The frame's own camera
 * hole sits in the status bar (no second punch-hole drawn). The app was recorded at exactly
 * the area between the status bar (52 css px, clears the camera) and the gesture inset (18).
 */
const STATUS_CSS = 52
const HOME_CSS = 18
export function flagshipPhone(parent: HTMLElement, mob: BeatMeta, height: number) {
  const H = height
  const W = Math.round((H * 1620) / 3136)
  const sw = W * 0.7901
  const sh = H * 0.9107
  const k = sw / mob.viewport.width // app css px → stage px
  const bar = STATUS_CSS * k
  const home = sh - bar - mob.viewport.height * k
  const el_ = el('div', { class: 'v6-phone', style: `width:${W}px;height:${H}px` })
  const screen = el('div', { class: 'v6-screen', style: `left:${(W * 0.1049).toFixed(2)}px;top:${(H * 0.0453).toFixed(2)}px;width:${sw.toFixed(2)}px;height:${sh.toFixed(2)}px;border-radius:15.08% / 6.76%` })
  const fs = Math.round(14 * k)
  // text sits on the camera's centre line (camera spans 16.5–44.8 css px)
  const status = el('div', { class: 'v6-status', style: `height:${bar.toFixed(2)}px;font-size:${fs}px;padding:${(8 * k).toFixed(1)}px ${(26 * k).toFixed(1)}px 0` },
    el('span', {}, '9:41'),
    el('span', { class: 'v6-icons', html: `<svg viewBox="0 0 52 14" height="${fs}"><path d="M2 12h2v-2H2zm4 0h2V8H6zm4 0h2V5h-2zm4 0h2V2h-2z" fill="currentColor"/><path d="M27 12.5l-6-6.2a8.6 8.6 0 0 1 12 0z" fill="currentColor"/><rect x="38" y="3" width="11" height="8" rx="1.6" fill="none" stroke="currentColor" stroke-width="1.3"/><rect x="39.6" y="4.6" width="7" height="4.8" rx="0.8" fill="currentColor"/><rect x="49.6" y="5.6" width="1.4" height="2.8" rx="0.6" fill="currentColor"/></svg>` }))
  const video = el('video', { muted: true, playsinline: true, preload: 'auto', src: srcOf(mob), style: `width:${sw.toFixed(2)}px;height:${(mob.viewport.height * k).toFixed(2)}px;display:block;flex:none` }) as HTMLVideoElement
  video.muted = true
  const bottom = el('div', { class: 'v6-home', style: `height:${home.toFixed(2)}px` }, el('i', { class: 'v6-pill', style: `width:${Math.round(sw * 0.3)}px` }))
  screen.append(status, video, bottom)
  const frame = el('img', { class: 'v6-frame', src: './pixel-9-pro.webp', style: `width:${W}px;height:${H}px` })
  const gloss = el('div', { class: 'v4-gloss', style: 'border-radius: 15.08% / 6.76%' })
  screen.append(gloss)
  el_.append(screen, frame)
  parent.append(el_)
  return { el: el_, video, gloss, W, H }
}

// ---------------------------------------------------------------- cold open (experiment)
/** quick on-beat cuts between real moments from later beats, each with a small push */
export const montage: SceneBuilder = ({ root, s, dur }) => {
  const cuts = (s as any).cuts as { beat: BeatMeta; t: number; rect?: Rect; z: number }[]
  const each = dur / cuts.length
  const world = el('div', { class: 'world' })
  root.append(world)
  const wins = cuts.map((c) => {
    const g = glassWindow(world, c.beat)
    const scale = g.W / c.beat.viewport.width
    const body = { x: 960 - g.W / 2, y: 540 - g.H / 2 + WIN.bar, w: g.W, h: g.bh }
    const map = (x: number, y: number) => ({ x: body.x + x * scale, y: body.y + y * scale })
    const view = c.rect ? focusView(c.rect, map, body, scale, c.z) : { x: 960, y: 540, z: c.z }
    return { g, c, view }
  })
  wins.forEach((_, i) => cue(s.start + i * each, i === 0 ? 'impact' : 'click', i === 0 ? 0.6 : 0.4))
  return Object.assign(
    (lt: number) => {
      const i = Math.min(cuts.length - 1, Math.floor(lt / each))
      wins.forEach((w, k) => css(w.g.win, { opacity: k === i ? '1' : '0' }))
      const w = wins[i]
      const p = clamp((lt - i * each) / each)
      const z = w.view.z * (1 + 0.06 * p)
      place(w.g.win, w.g.W, w.g.H, { x: 960, y: 540 })
      css(world, { transform: `translate(960px,540px) scale(${z.toFixed(4)}) translate(${(-w.view.x).toFixed(1)}px,${(-w.view.y).toFixed(1)}px)` })
      css(root, { opacity: (1 - ep(lt, dur - 0.12, dur)).toFixed(3) })
    },
    {
      seek: async (lt: number) => {
        const i = Math.min(cuts.length - 1, Math.floor(lt / each))
        const w = wins[i]
        await seekVideo(w.g.video, w.c.t + (lt - i * each))
      },
    }
  )
}

// ---------------------------------------------------------------- reveal + CTA
/** logo forms with a light burst, then the product window rises out of the depth */
export const reveal: SceneBuilder = ({ root, s, dur }) => {
  const b = (s as any).beat as BeatMeta
  const mark = el('div', { class: 'v3-mark' }, logo(140))
  const word = el('div', { class: 'v3-word' }, 'Lupyd')
  const lockup = el('div', { class: 'v3-lockup' }, mark, word)
  const ring = el('div', { class: 'v4-ring' })
  root.append(ring, lockup)
  const world = el('div', { class: 'world' })
  world.style.perspective = '2200px'
  root.append(world)
  const g = glassWindow(world, b) // lands in exactly the DM shot's frame
  const W0 = Math.max(1.5, dur - 1.35) // window starts rising once the logo has cleared
  cue(s.start + 0.05, 'impact', 0.8)
  cue(s.start + W0, 'whoosh', 0.55)
  return Object.assign(
    (lt: number) => {
      const m = spring(lt - 0.05, { stiffness: 200, damping: 18 })
      const lo = ep(lt, W0 - 0.55, W0 - 0.05, ease.inCubic)
      css(lockup, { transform: `translate(-50%, -62%) translateY(${(-40 * lo).toFixed(1)}px) scale(${(1 - 0.08 * lo).toFixed(4)})`, opacity: (1 - lo).toFixed(3) })
      css(mark, { transform: `scale(${(0.5 + 0.5 * m).toFixed(4)})`, opacity: clamp(m * 1.5).toFixed(3) })
      css(word, { clipPath: `inset(0 ${((1 - outExpo(clamp((lt - 0.25) / 0.5))) * 100).toFixed(2)}% 0 0)` })
      const rp = ep(lt, 0.05, 1.3)
      css(ring, { transform: `translate(-50%,-50%) scale(${(0.4 + 2.2 * rp).toFixed(3)})`, opacity: ((1 - rp) * 0.6).toFixed(3) })
      const wi = ep(lt, W0, dur - 0.05)
      place(g.win, g.W, g.H, { x: 960, y: lerp(1000, 540, wi), z: lerp(-900, 0, wi), rx: lerp(40, 0, wi), o: lt >= W0 ? clamp(wi * 2) : 0 })
      sweep(g.gloss, clamp((lt - W0 - 0.3) / 1.1))
    },
    { seek: () => seekVideo(g.video, b.in) }
  )
}

export const cta: SceneBuilder = ({ root, s, L }) => {
  const c1 = L('cta1')
  const c3 = L('cta3')
  const mark = el('div', { class: 'v3-mark' }, logo(150))
  const word = el('div', { class: 'v3-word' }, 'Lupyd')
  const lockup = el('div', { class: 'v3-lockup' }, mark, word)
  const tag = el('div', { class: 'v3-tag' }, 'Private by design.')
  const url = el('div', { class: 'v4-url' }, 'lupyd.com')
  const ring = el('div', { class: 'v4-ring' })
  root.append(ring, lockup, tag, url)
  cue(s.start + c1.start - 0.3, 'impact', 0.7)
  cue(s.start + c3.start + 0.3, 'pop', 0.4)
  return (lt: number) => {
    root.style.opacity = clamp((lt + 0.2) / 0.2).toFixed(3)
    const m = spring(lt - (c1.start - 0.3), { stiffness: 200, damping: 18 })
    css(mark, { transform: `scale(${(0.5 + 0.5 * m).toFixed(4)})`, opacity: clamp(m * 1.5).toFixed(3) })
    css(word, { clipPath: `inset(0 ${((1 - outExpo(clamp((lt - c1.start + 0.1) / 0.5))) * 100).toFixed(2)}% 0 0)` })
    const rp = ep(lt, c1.start - 0.3, c1.start + 1.0)
    css(ring, { transform: `translate(-50%,-50%) scale(${(0.4 + 2.2 * rp).toFixed(3)})`, opacity: ((1 - rp) * 0.5).toFixed(3) })
    const tg = spring(lt - (c1.start + 0.6), { stiffness: 180, damping: 22 })
    css(tag, { opacity: clamp(tg * 1.4).toFixed(3), transform: `translate(-50%, 0) translateY(${((1 - tg) * 16).toFixed(1)}px)` })
    const u = spring(lt - (c3.start + 0.2), { stiffness: 180, damping: 20 })
    css(url, { opacity: clamp(u * 1.4).toFixed(3), transform: `translate(-50%, 0) translateY(${((1 - u) * 16).toFixed(1)}px) scale(${(0.92 + 0.08 * u).toFixed(4)})` })
  }
}
