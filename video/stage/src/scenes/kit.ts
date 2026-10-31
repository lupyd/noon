// Shared scene helpers: camera world, step-driven cursor paths, rect mapping.
import { Camera } from '../camera'
import type { CursorKey } from '../components'
import { div } from '../dom'
import type { AppWindow, Phone, Place, Rect } from '../frames'

export function world(root: HTMLElement, perspective = 2400) {
  const w = div('world')
  w.style.perspective = `${perspective}px`
  root.append(w)
  return { w, cam: new Camera(w) }
}

/** page rect (iframe css px) → world rect for an unrotated window/phone */
export function wrect(win: AppWindow | Phone, p: Place, r: Rect | null | undefined) {
  if (!r) return null
  const a = win.toStage(p, r[0], r[1])
  const b = win.toStage(p, r[0] + r[2], r[1] + r[3])
  return { x: a.x, y: a.y, w: b.x - a.x, h: b.y - a.y, cx: (a.x + b.x) / 2, cy: (a.y + b.y) / 2 }
}

/** rect of the i-th scripted step's target in world space */
export function stepRect(win: AppWindow | Phone, p: Place, i: number) {
  return wrect(win, p, (win.frame?.meta.rects as Record<number, Rect | null> | undefined)?.[i])
}

/**
 * Cursor keys for a list of clicks: rest at the previous point, then a quick
 * eased move that lands `land` seconds before the click (like a real hand).
 */
export function clickPath(start: { t: number; x: number; y: number }, clicks: { at: number; x: number; y: number; move?: number; noClick?: boolean }[], land = 0.08): CursorKey[] {
  const keys: CursorKey[] = [{ t: start.t, x: start.x, y: start.y }]
  let px = start.x
  let py = start.y
  let pt = start.t
  for (const c of clicks) {
    const mv = c.move ?? Math.min(0.65, Math.max(0.32, Math.hypot(c.x - px, c.y - py) / 900))
    const t0 = Math.max(pt + 0.05, c.at - land - mv)
    keys.push({ t: t0, x: px, y: py })
    keys.push({ t: c.at - land, x: c.x, y: c.y })
    if (!c.noClick) keys.push({ t: c.at, x: c.x, y: c.y, click: true })
    px = c.x
    py = c.y
    pt = c.at
  }
  return keys
}

/** "11:59 PM" + d minutes */
export function addMin(hm: string, d: number) {
  const m = hm.match(/(\d{1,2}):(\d{2})\s?([AP]M)/)
  if (!m) return hm
  let mins = ((+m[1] % 12) + (m[3] === 'PM' ? 12 : 0)) * 60 + +m[2] + d
  mins = ((mins % 1440) + 1440) % 1440
  const h = Math.floor(mins / 60)
  return `${((h + 11) % 12) + 1}:${String(mins % 60).padStart(2, '0')} ${h >= 12 ? 'PM' : 'AM'}`
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** world rect of a placed (unrotated) window or phone */
export function boxOf(win: AppWindow | Phone, p: Place) {
  const s = p.s ?? 1
  return { x: p.x - (win.W / 2) * s, y: p.y - (win.H / 2) * s, w: win.W * s, h: win.H * s }
}
