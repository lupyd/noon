// Noon scenes: the animated logo (intro and end card), the problem card, the
// respondent's phone, and the blind-signature beat built from the respondent's
// real answer. Desktop clips use the shared v4 `clip` scene.
import { cue } from '../cues'
import { css, el, icon } from '../dom'
import { clamp, ease, lerp, spring } from '../motion'
import { clipAt, stageAt } from '../timemap'
import type { SceneBuilder } from '../types'
import { encrypt, scramble } from '../components'
import { type BeatMeta, seekVideo } from './v3'
import { TITLE, ep, flagshipPhone, inOut, place, sweep, titleCard } from './v4'
// @ts-ignore plain JS module shared with logo/index.html
import { CONTENT_C, CONTENT_H, LOGO, createLogo } from '../../../logo/engine.js'
import svgUrl from '../../../logo/noon-logo.svg?url'

const W = 1920
const H = 1080
const DRAFT = new URLSearchParams(location.search).get('q') === 'draft'
const smooth = (u: number) => u * u * (3 - 2 * u)
const outQuint = (u: number) => 1 - Math.pow(1 - u, 5)
const inOutCubic = ease.inOutCubic
const p01 = (t: number, a: number, b: number) => clamp((t - a) / (b - a))
/** ∫ smooth(u) du from 0 to u, so a speed ramp integrates to a continuous angle */
const smoothInt = (u: number) => (u <= 0 ? 0 : u >= 1 ? u - 0.5 : u * u * u - (u * u * u * u) / 2)

// ---------------------------------------------------------------- logo
// One WebGL canvas for the whole film (never two contexts at once); it moves
// into whichever logo scene is alive.
const canvas = el('canvas', { class: 'noon-logo-canvas' }) as HTMLCanvasElement
const dpr = window.devicePixelRatio || 1
canvas.width = Math.round(W * dpr)
canvas.height = Math.round(H * dpr)
let logo: any = null
// created on first use, so render workers that only cover app clips never pay for it
let logoReady: Promise<void> | null = null
const ensureLogo = () =>
  (logoReady ??= createLogo(canvas, { svgUrl, tex: 4096, starTex: DRAFT ? 2048 : 4096, detail: DRAFT ? 1024 : 2048 }).then((l: any) => {
    logo = l
  }))

const SPIN = 28 // spiral rotation, degrees per second at full speed
/** logo square [x, y, size] (CSS px) that frames the content at `h` of the height, centred on (cx, cy) */
function frameAt(cx: number, cy: number, h: number, focus = CONTENT_C) {
  const size = (h * H * LOGO) / CONTENT_H
  return [cx - (focus[0] / LOGO) * size, cy - (focus[1] / LOGO) * size, size]
}

/**
 * kind 'logo'. mode 'intro': open inside a sun's spiral, pull out as the
 * spirals then the flames come alive, slide left, "Introducing Noon".
 * mode 'outro': the whole logo, alive; it slides left for the end card.
 */
export const logoScene: SceneBuilder = ({ root, s, dur }) => {
  const mode = (s as any).mode ?? 'intro'
  const intro = mode === 'intro'
  const T = intro
    ? { spin: [0, 0.9], zoom: [0.2, 3.6], flames: [1.6, 3.4], slide: [4.1, 5.2], l1: [4.55, 5.3], l2: [4.7, 5.5], l3: [99, 99] }
    : { spin: [-30, -29], zoom: [-1, -0.5], flames: [-1, -0.5], slide: [0.7, 1.8], l1: [1.05, 1.8], l2: [1.3, 2.1], l3: [1.6, 2.4] }
  const ZOOM0 = 4.6
  const title = el('div', { class: 'noon-title' })
  const lines = intro
    ? [el('div', { class: 'nt-intro' }, 'Introducing'), el('div', { class: 'nt-name' }, 'Noon')]
    : [el('div', { class: 'nt-name' }, 'Noon'), el('div', { class: 'nt-tag' }, 'Honest answers, by design.'), el('div', { class: 'nt-url' }, 'noon.lupyd.com')]
  title.append(...lines)
  const black = el('div', { class: 'layer', style: 'background:#000;opacity:0' })
  root.append(title, black)
  const ranges = intro ? [T.l1, T.l2] : [T.l1, T.l2, T.l3]
  cue(s.start + T.slide[0], 'whoosh', 0.35)
  if (intro) cue(s.start + T.zoom[0], 'whoosh', 0.25)

  const update = (lt: number) => {
    if (canvas.parentElement !== root) root.prepend(canvas)
    if (!logo) void ensureLogo()
    // the film's clock for the flames runs on scene time; the spin integrates its ramp
    const sp = T.spin[1] - T.spin[0]
    const angle = ((SPIN * Math.PI) / 180) * sp * smoothInt((lt - T.spin[0]) / sp)
    const amp = smooth(p01(lt, T.flames[0], T.flames[1]))
    // camera: zoom eased in log space; the focus travels in proportion to the view width
    const z = Math.exp(Math.log(ZOOM0) * (1 - inOutCubic(p01(lt, T.zoom[0], T.zoom[1]))))
    const w = (1 / z - 1 / ZOOM0) / (1 - 1 / ZOOM0)
    const f0 = logo?.suns[0].c ?? CONTENT_C
    const focus = [f0[0] + (CONTENT_C[0] - f0[0]) * w, f0[1] + (CONTENT_C[1] - f0[1]) * w]
    const sl = outQuint(p01(lt, T.slide[0], T.slide[1]))
    const r = frameAt(lerp(W / 2, W * 0.3, sl), H / 2, 0.82 * z * lerp(1, 0.8, sl), focus)
    if (logo) logo.draw({ t: s.start + lt, amp, angle, rect: r.map((v) => v * dpr) })
    ranges.forEach((rg, i) => {
      const u = outQuint(p01(lt, rg[0], rg[1]))
      css(lines[i], { opacity: u.toFixed(3), transform: `translateY(${((1 - u) * 36).toFixed(1)}px)` })
    })
    css(black, { opacity: intro ? '0' : ep(lt, dur - 0.7, dur, ease.inCubic).toFixed(3) })
  }
  return Object.assign(update, { seek: async (lt: number) => (await ensureLogo(), update(lt)) })
}

// ---------------------------------------------------------------- type card
/** one large statement, wrapped, held for the line */
export const statement: SceneBuilder = ({ root, s, dur }) => {
  const e = el('div', { class: 'noon-statement' }, ((s as any).cards ?? [''])[0])
  root.append(e)
  return (lt) => {
    const p = spring(lt - 0.05, { stiffness: 170, damping: 22 })
    const q = ep(lt, dur - 0.35, dur, ease.inCubic)
    css(e, { opacity: (clamp(p * 1.4) * (1 - q)).toFixed(3), transform: `translate(-50%, -50%) translateY(${((1 - p) * 28 - q * 18).toFixed(1)}px)` })
  }
}

// ---------------------------------------------------------------- phone
/** the respondent's phone: one device, centred, the real recording at its speed ramp; taps ripple */
export const phoneScene: SceneBuilder = ({ root, s, dur }) => {
  const b = (s as any).beat as BeatMeta
  const sp = (b as any).speed
  const title = titleCard(root, (s as any).title)
  const off = title ? TITLE.done - 0.1 : 0
  const world = el('div', { class: 'world' })
  world.style.perspective = '2200px'
  root.append(world)
  const ph = flagshipPhone(world, b, H - 2 * 44)
  // screen geometry (see flagshipPhone): app css px → phone-local px
  const k = (ph.W * 0.7901) / b.viewport.width
  const sx = ph.W * 0.1049
  const sy = ph.H * 0.0453 + 52 * k
  const taps = b.actions.filter((a) => a.kind === 'click' && a.rect)
  const ripple = el('div', { class: 'noon-tap' })
  ph.el.append(ripple)
  const S0 = s.start + off
  const clipT = (lt: number) => clipAt(sp, b.in, Math.max(0, lt - off))
  for (const a of taps) if (a.t >= b.in && a.t <= b.out) cue(S0 + stageAt(sp, b.in, a.t), 'click', 0.35)
  for (const a of b.actions) if (a.kind === 'type' && a.t >= b.in) for (let i = 0; i < ((a as any).text?.length ?? 0); i += 2) cue(S0 + stageAt(sp, b.in, a.t + (i / (a as any).text.length) * ((a.end ?? a.t) - a.t)), 'key', 0.1)
  const update = (lt: number) => {
    title?.(lt)
    const io = inOut(lt, dur, 'rise', 'recede', title ? TITLE.done : 0)
    place(ph.el, ph.W, ph.H, { x: W / 2, y: H / 2, z: io.z, rx: io.rx, s: io.s, o: io.o, blur: io.blur })
    sweep(ph.gloss, clamp((lt - off + 0.2) / 1.2))
    const ct = clipT(lt)
    const tap = [...taps].reverse().find((a) => ct >= a.t && ct < a.t + 0.5)
    if (tap && lt >= off) {
      const r = tap.rect as number[]
      const u = (ct - tap.t) / 0.5
      css(ripple, { left: `${(sx + (r[0] + r[2] / 2) * k).toFixed(1)}px`, top: `${(sy + (r[1] + r[3] / 2) * k).toFixed(1)}px`, opacity: ((1 - u) * 0.8).toFixed(3), transform: `translate(-50%, -50%) scale(${(0.4 + u).toFixed(3)})` })
    } else css(ripple, { opacity: '0' })
  }
  return Object.assign(update, { seek: (lt: number) => seekVideo(ph.video, Math.min(clipT(lt), b.out)) })
}

// ---------------------------------------------------------------- blind signature
/**
 * The respondent's real answer, with her address on it. The browser blinds it
 * (text locks into noise), the Noon server signs the blinded value, then the
 * two travel apart: the address to the verified list, the answer, unblinded and
 * carrying the signature, to the responses. Nothing links them afterwards.
 */
const OTHERS_ANSWERS = ['On-call rotation is uneven.', 'Staging is broken more often than it works.', 'Honestly fine right now.']
const OTHERS_EMAILS = ['jordan.ellis@halcyonlabs.io', 'sam.okafor@halcyonlabs.io', 'lena.fischer@halcyonlabs.io']
export const blind: SceneBuilder = ({ root, s, dur }) => {
  const msg = (s as any).message as string
  const email = (s as any).email as string
  const S0 = s.start
  const T = { lockA: 0.9, lockB: 1.9, go: 2.2, at: 3.0, sign: 3.15, split: 3.7, land: 4.7, unA: 4.6, unB: 5.5, rest: 5.6 }
  cue(S0 + T.lockB - 0.15, 'lock', 0.7)
  cue(S0 + T.go, 'whoosh', 0.4)
  cue(S0 + T.sign, 'data', 0.5)
  cue(S0 + T.split, 'whoosh', 0.45)
  cue(S0 + T.unB - 0.2, 'unlock', 0.55)

  const world = el('div', { class: 'world' })
  root.append(world)
  const server = el('div', { class: 'v4-node noon-server' }, icon('server', 46, 1.6))
  const serverLabel = el('div', { class: 'noon-node-label' }, 'Noon')
  const head = el('div', { class: 'nb-head' }, el('span', { class: 'nb-from' }, email))
  const lockI = icon('lock', 20, 2.2)
  const sealI = icon('shieldCheck', 22, 2)
  const body = el('div', { class: 'nb-body' })
  const card = el('div', { class: 'noon-card' }, el('div', { class: 'nb-icons' }, lockI, sealI), body)
  const colL = el('div', { class: 'noon-col-h', style: 'left:250px' }, 'Responses')
  const colR = el('div', { class: 'noon-col-h', style: 'left:1180px' }, 'Verified respondents')
  const ghostsL = OTHERS_ANSWERS.map((a) => el('div', { class: 'noon-ghost' }, a))
  const ghostsR = OTHERS_EMAILS.map((a) => el('div', { class: 'noon-ghost mono' }, a))
  const divider = el('div', { class: 'noon-divider' })
  world.append(colL, colR, divider, ...ghostsL, ...ghostsR, server, serverLabel, card, head)

  const CW = 840
  return (lt) => {
    const io = inOut(lt, dur, 'rise', 'recede')
    css(world, { opacity: io.o.toFixed(3) })
    // body text: plain → blinded noise → (after signing) unblinded again
    body.textContent = lt < T.split ? encrypt(msg, lt, T.lockA, T.lockB, 5) : scramble(msg, lt, T.unA, T.unB, 5)
    const locked = lt >= T.lockB - 0.15 && lt < T.unB - 0.1
    css(body, { color: locked ? 'var(--mint)' : '#f4f4f6', fontFamily: lt > T.lockA && lt < T.unB ? 'var(--mono)' : 'var(--sans)' })
    const lb = spring(lt - (T.lockB - 0.15), { stiffness: 320, damping: 14 })
    css(lockI, { opacity: locked ? '1' : '0', transform: `scale(${(0.6 + 0.4 * lb).toFixed(3)})` })
    const sb = spring(lt - T.sign, { stiffness: 300, damping: 13 })
    css(sealI, { opacity: lt > T.sign ? '1' : '0', transform: `scale(${(lt > T.sign ? 0.5 + 0.5 * sb : 0).toFixed(3)})`, color: 'var(--mint)' })

    // server
    const sIn = spring(lt - 1.5, { stiffness: 160, damping: 18 })
    const pulse = lt > T.sign ? Math.exp(-(lt - T.sign) * 5) : 0
    css(server, { left: `${960 - 58}px`, top: `${190 - 58}px`, opacity: clamp(sIn * 1.5).toFixed(3), transform: `scale(${(0.85 + 0.15 * sIn + 0.12 * pulse).toFixed(4)})`, boxShadow: `0 0 0 ${(1 + 10 * pulse).toFixed(1)}px rgba(124,240,196,${(0.12 + 0.4 * pulse).toFixed(3)}), 0 30px 60px -20px rgba(0,0,0,0.9)` })
    css(serverLabel, { left: '960px', top: '268px', opacity: clamp(sIn * 1.5).toFixed(3) })

    // card path: centre → up to the server (small) → down-left to the responses column
    const rise = spring(lt, { stiffness: 150, damping: 20 })
    const go = ep(lt, T.go, T.at, inOutCubic)
    const split = ep(lt, T.split, T.land, inOutCubic)
    const cx = lerp(lerp(960, 960, go), 620, split)
    const cy = lerp(lerp(560 + (1 - rise) * 40, 330, go), 450, split)
    const cs = lerp(lerp(1, 0.55, go), 0.82, split)
    const ch = card.offsetHeight || 150
    css(card, { width: `${CW}px`, opacity: clamp(rise * 1.4).toFixed(3), transform: `translate(${(cx - CW / 2).toFixed(1)}px, ${(cy - ch / 2).toFixed(1)}px) scale(${cs.toFixed(4)})` })
    // the address: rides on the card's top edge, then peels off to the verified column
    const hx = lerp(cx - (CW / 2) * cs + 30 * cs, 1180, split)
    const hy = lerp(cy - (ch / 2) * cs - 46 * cs, 372, split)
    const hs = lerp(cs, 1, split)
    css(head, { opacity: clamp(rise * 1.4).toFixed(3), transform: `translate(${hx.toFixed(1)}px, ${hy.toFixed(1)}px) scale(${hs.toFixed(4)})` })

    // the two columns settle in with the other (faint) entries
    const cols = ep(lt, T.rest - 0.6, T.rest + 0.6)
    css(colL, { opacity: cols.toFixed(3) })
    css(colR, { opacity: cols.toFixed(3) })
    css(divider, { opacity: (cols * 0.7).toFixed(3), transform: `scaleY(${cols.toFixed(3)})` })
    ghostsL.forEach((g, i) => {
      const u = ep(lt, T.rest + i * 0.12, T.rest + 0.7 + i * 0.12)
      css(g, { left: '250px', top: `${600 + i * 70}px`, opacity: (u * 0.42).toFixed(3), transform: `translateY(${((1 - u) * 14).toFixed(1)}px)` })
    })
    ghostsR.forEach((g, i) => {
      const u = ep(lt, T.rest + 0.06 + i * 0.12, T.rest + 0.76 + i * 0.12)
      css(g, { left: '1180px', top: `${440 + i * 62}px`, opacity: (u * 0.42).toFixed(3), transform: `translateY(${((1 - u) * 14).toFixed(1)}px)` })
    })
  }
}
