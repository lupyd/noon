// Live chat choreography inside a real, frozen app page.
//
// New messages are clones of the app's own rows (same markup, classes, fonts),
// appended to the app's message list in DOM order, so the app's layout decides
// alignment: an outgoing message always lands on its own row under the last one.
// (The old stage overlaid free-floating bubbles at a measured y, and those rows
// went stale when the app re-rendered its list.) Rows are revealed by time, the
// list glides up as each one lands, a typing indicator precedes incoming bursts,
// and replies / reactions use the app's own quote + reaction-chip markup.
import type { FrameCtx } from './frames'
import { clamp, ease, prog, spring, springs } from './motion'

export interface ChatLine {
  /** absolute timeline seconds when the message lands */
  at: number
  /** 'me' (outgoing) or the sender's username (incoming) */
  from: string
  text: string
  /** seconds of "typing…" before `at` (incoming only) */
  typing?: number
  /** quoted message this one replies to */
  reply?: { who: string; text: string }
  /** reaction landing on this message */
  react?: { at: number; emoji: string; count?: number; mine?: boolean }
  /** group only: role badge next to the name */
  role?: string
  /** group only: avatar url */
  avatar?: string
  /** timestamp label */
  time?: string
}

export interface ChatState {
  scroller: HTMLElement
  rows: { line: ChatLine; el: HTMLElement; h: number; react?: HTMLElement }[]
  typing: HTMLElement
  typingH: number
  dots: HTMLElement[]
  base: number
  doc: Document
}

const deepest = (e: Element | null): HTMLElement | null => {
  if (!e) return null
  let c = e as HTMLElement
  while (c.firstElementChild && c.children.length === 1 && c.firstElementChild.tagName === 'DIV') c = c.firstElementChild as HTMLElement
  return c
}

function findScroller(doc: Document) {
  return [...doc.querySelectorAll<HTMLElement>('*')]
    .filter((e) => visible(e) && e.scrollHeight > e.clientHeight + 60 && e.clientHeight > 200 && getComputedStyle(e).overflowY !== 'visible')
    .sort((a, b) => b.scrollHeight - a.scrollHeight)[0]
}

function reactionBar(doc: Document, emoji: string, count: number, mine: boolean, right: boolean) {
  const bar = doc.createElement('div')
  bar.className = `flex flex-wrap items-center gap-1 mt-1 z-10 select-none ${right ? 'justify-end' : 'justify-start'}`
  const b = doc.createElement('span')
  b.className = `inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${mine ? 'bg-foreground/10 dark:bg-white/15 border-foreground/30 dark:border-white/30 text-foreground font-semibold' : 'bg-muted/40 border-border/50 text-muted-foreground'}`
  const e = doc.createElement('span')
  e.className = 'text-[13px] leading-none'
  e.textContent = emoji
  const n = doc.createElement('span')
  n.className = 'text-[11px] leading-none font-mono'
  n.textContent = String(count)
  b.append(e, n)
  bar.append(b)
  return bar
}

function quote(doc: Document, who: string, text: string, kind: 'dm-me' | 'dm-them' | 'group') {
  const q = doc.createElement('div')
  q.className =
    kind === 'group'
      ? 'mb-1.5 px-2.5 py-1 rounded-lg border-l-2 border-primary bg-muted/60 text-xs max-w-lg'
      : `mb-1.5 px-2.5 py-1 rounded-lg border-l-2 text-xs ${kind === 'dm-me' ? 'bg-black/10 dark:bg-white/10 border-primary-foreground/70' : 'bg-gray-100 dark:bg-neutral-700/60 border-primary'}`
  const a = doc.createElement('div')
  a.className = kind === 'group' ? 'font-semibold text-[11px] text-primary truncate' : 'font-semibold text-[11px] truncate opacity-90'
  a.textContent = who
  const b = doc.createElement('div')
  b.className = kind === 'group' ? 'text-[11px] text-muted-foreground truncate' : 'text-[11px] truncate opacity-75'
  b.textContent = text
  q.append(a, b)
  return q
}

function dotsEl(doc: Document) {
  const w = doc.createElement('span')
  w.style.cssText = 'display:inline-flex;gap:4px;align-items:center;height:20px;padding:0 2px'
  const dots = [0, 1, 2].map(() => {
    const d = doc.createElement('i')
    d.style.cssText = 'display:block;width:7px;height:7px;border-radius:50%;background:currentColor;opacity:.4'
    w.append(d)
    return d
  })
  return { w, dots }
}

const visible = (e: Element) => {
  const r = e.getBoundingClientRect()
  return r.width > 0 && r.height > 0
}

/**
 * Wait until the thread is really laid out (visible rows + composer, stable for
 * ~1 s), then freeze the app BEFORE we clone into it: a re-render after cloning
 * (cached page swap, scroll-to-latest) would otherwise drop our rows on some
 * render workers and not others.
 */
export async function readyThread(c: FrameCtx, rowSel: string, min = 6) {
  const { doc, win } = c
  let last = ''
  let stable = 0
  for (let i = 0; i < 120 && stable < 6; i++) {
    const rows = [...doc.querySelectorAll(rowSel)].filter(visible)
    const comp = [...doc.querySelectorAll('input,textarea')].filter(visible).pop()
    const sig = rows.length >= min && comp ? `${rows.length}|${Math.round(comp.getBoundingClientRect().y)}|${doc.body.innerText.length}` : ''
    stable = sig && sig === last ? stable + 1 : 0
    last = sig
    await new Promise((r) => setTimeout(r, 200))
  }
  win.__stageFreeze?.()
}

/** DM thread (/messages/:user): clone the last incoming / outgoing rows */
export function setupDm(c: FrameCtx, lines: ChatLine[]): ChatState | null {
  const { doc } = c
  const rowsAll = [...doc.querySelectorAll<HTMLElement>('[id^="user-msg-"]')].filter(visible)
  if (!rowsAll.length) return null
  const list = rowsAll[rowsAll.length - 1].parentElement!
  const plain = (r: HTMLElement) => !r.querySelector('video,img,audio,svg.lucide-pin') && !!r.querySelector('.lupyd-markdown')
  const tIn = [...rowsAll].reverse().find((r) => plain(r) && r.querySelector('.justify-start'))
  const tOut = [...rowsAll].reverse().find((r) => plain(r) && r.querySelector('.justify-end'))
  if (!tIn || !tOut) return null
  const scroller = findScroller(doc)
  const mk = (line: ChatLine, i: number) => {
    const me = line.from === 'me'
    const row = (me ? tOut : tIn).cloneNode(true) as HTMLElement
    row.id = `stage-msg-${i}`
    row.querySelectorAll('[id]').forEach((e) => (e.id = `stage-${i}-${e.id}`))
    const md = row.querySelectorAll('.lupyd-markdown')
    const textEl = (md[md.length - 1] as HTMLElement) ?? deepest(row.querySelector('.text-sm'))
    if (textEl) textEl.textContent = line.text
    const time = row.querySelector('.text-\\[10px\\] span')
    if (time && line.time) time.textContent = line.time
    if (line.reply) {
      const body = row.querySelector('.text-sm.break-words')
      body?.parentElement?.insertBefore(quote(doc, line.reply.who, line.reply.text, me ? 'dm-me' : 'dm-them'), body)
    }
    let react: HTMLElement | undefined
    if (line.react) {
      const bubble = row.querySelector('[id^="stage-"][id*="msg-"]') ?? row.querySelector('.group')
      react = reactionBar(doc, line.react.emoji, line.react.count ?? 1, !!line.react.mine, me)
      react.style.cssText = `padding:0 6px;${me ? '' : ''}`
      bubble?.parentElement?.append(react)
    }
    list.append(row)
    return { line, el: row, h: 0, react }
  }
  const rows = lines.map(mk)
  // typing bubble: an incoming row whose content is three dots
  const typing = tIn.cloneNode(true) as HTMLElement
  typing.id = 'stage-typing'
  typing.querySelectorAll('[id]').forEach((e) => e.removeAttribute('id'))
  const tBody = typing.querySelector('.text-sm.break-words') as HTMLElement | null
  const { w, dots } = dotsEl(doc)
  if (tBody) {
    tBody.textContent = ''
    tBody.append(w)
  }
  typing.querySelector('.text-\\[10px\\]')?.remove()
  list.append(typing)
  return finish(doc, scroller, rows, typing, dots)
}

/** group channel (/groups/:id?c=n): clone the last plain row (avatar, name, role, time) */
export function setupGroup(c: FrameCtx, lines: ChatLine[], avatars: Record<string, string> = {}): ChatState | null {
  const { doc } = c
  const all = [...doc.querySelectorAll<HTMLElement>('[id^="group-msg-"]')].filter(visible)
  if (!all.length) return null
  const plain = (r: HTMLElement) => !r.querySelector('video,audio,.aspect-video') && !!r.querySelector('.lupyd-markdown') && r.querySelectorAll('img').length <= 1
  const tpl = ([...all].reverse().find((r) => plain(r) && r.querySelector('span.rounded-full.border')) ?? all[all.length - 1]).closest('.relative.touch-pan-y') as HTMLElement
  const list = tpl.parentElement!
  const tail = list.lastElementChild // h-4 spacer stays last
  const scroller = findScroller(doc)
  // each sender's real avatar node (photo or first-letter) and role badge
  const who: Record<string, { av?: Element; badge?: Element | null }> = {}
  for (const r of all) {
    const n = (r.querySelector('button.text-sm.font-semibold')?.textContent || '').trim()
    if (n && !who[n]) who[n] = { av: r.querySelector(':scope > button') ?? undefined, badge: r.querySelector('span.rounded-full.border') }
  }
  void avatars
  const mk = (line: ChatLine, i: number) => {
    const row = tpl.cloneNode(true) as HTMLElement
    row.querySelectorAll('[id]').forEach((e) => (e.id = `stage-${i}-${e.id}`))
    const sender = line.from === 'me' ? 'alex' : line.from
    const name = row.querySelector('button.text-sm.font-semibold') as HTMLElement | null
    if (name) name.textContent = sender
    const src = who[sender]
    const avBtn = row.querySelector('[id^="stage-"] > button') as HTMLElement | null
    if (avBtn && src?.av) avBtn.replaceWith(src.av.cloneNode(true))
    row.querySelectorAll('button[title]').forEach((b) => b.setAttribute('title', `Chat with @${sender}`))
    const badge = row.querySelector('span.rounded-full.border') as HTMLElement | null
    if (badge) {
      if (line.role) badge.textContent = line.role
      else if (src?.badge) badge.replaceWith(src.badge.cloneNode(true))
      else badge.remove()
    } else if (src?.badge && name) name.after(src.badge.cloneNode(true))
    const time = row.querySelector('.text-\\[11px\\].text-muted-foreground') as HTMLElement | null
    if (time && line.time) time.textContent = line.time
    const md = row.querySelectorAll('.lupyd-markdown')
    const textEl = md[md.length - 1] as HTMLElement | undefined
    if (textEl) textEl.textContent = line.text
    if (line.reply) {
      const body = row.querySelector('.text-sm.text-foreground')
      body?.parentElement?.insertBefore(quote(doc, line.reply.who, line.reply.text, 'group'), body)
    }
    let react: HTMLElement | undefined
    if (line.react) {
      const body = row.querySelector('.text-sm.text-foreground')?.parentElement
      react = reactionBar(doc, line.react.emoji, line.react.count ?? 1, !!line.react.mine, false)
      body?.parentElement?.append(react)
    }
    list.insertBefore(row, tail)
    return { line, el: row, h: 0, react }
  }
  const rows = lines.map(mk)
  const typing = doc.createElement('div')
  typing.className = 'px-4 py-1 text-xs text-muted-foreground flex items-center gap-2'
  const { w, dots } = dotsEl(doc)
  w.style.height = '14px'
  const label = doc.createElement('span')
  typing.append(w, label)
  list.insertBefore(typing, tail)
  ;(typing as any).__who = label
  return finish(doc, scroller, rows, typing, dots)
}

function finish(doc: Document, scroller: HTMLElement, rows: ChatState['rows'], typing: HTMLElement, dots: HTMLElement[]): ChatState {
  // measure every row at full size, then hide everything that hasn't landed
  for (const r of rows) {
    r.el.style.display = ''
    const cs = getComputedStyle(r.el)
    r.h = r.el.offsetHeight + parseFloat(cs.marginTop || '0') + parseFloat(cs.marginBottom || '0')
  }
  const cs = getComputedStyle(typing)
  const typingH = typing.offsetHeight + parseFloat(cs.marginTop || '0') + parseFloat(cs.marginBottom || '0')
  for (const r of rows) r.el.style.display = 'none'
  typing.style.display = 'none'
  scroller.scrollTop = scroller.scrollHeight
  return { scroller, rows, typing, typingH, dots, base: 0, doc }
}

const REVEAL = { stiffness: 210, damping: 24 }

/** time-driven: which rows exist, how far the list has glided, typing dots */
export function seekChat(st: ChatState | null, t: number) {
  if (!st) return
  let pending = 0 // px of not-yet-settled growth at the bottom
  let typingVis = false
  let typingWho = ''
  for (let i = 0; i < st.rows.length; i++) {
    const r = st.rows[i]
    const L = r.line
    const on = t >= L.at
    const disp = on ? '' : 'none'
    if (r.el.style.display !== disp) r.el.style.display = disp
    if (on) {
      const p = spring(t - L.at, REVEAL)
      pending += r.h * (1 - clamp(p))
      const me = L.from === 'me'
      r.el.style.transformOrigin = me ? '100% 100%' : '0% 100%'
      r.el.style.transform = p < 0.999 ? `translateY(${((1 - p) * 10).toFixed(2)}px) scale(${(0.94 + 0.06 * p).toFixed(4)})` : ''
      r.el.style.opacity = clamp(p * 1.8).toFixed(3)
    }
    if (r.react) {
      const ra = L.react!.at
      const q = spring(t - ra, springs.pop)
      const show = t >= ra
      r.react.style.visibility = show ? 'visible' : 'hidden'
      r.react.style.transformOrigin = L.from === 'me' ? '100% 0%' : '0% 0%'
      r.react.style.transform = show ? `scale(${(0.4 + 0.6 * q).toFixed(4)})` : 'scale(0.4)'
    }
    if (!on && L.typing && t >= L.at - L.typing) {
      typingVis = true
      typingWho = L.from
    }
  }
  const tv = typingVis ? '' : 'none'
  if (st.typing.style.display !== tv) st.typing.style.display = tv
  if (typingVis) {
    const who = (st.typing as any).__who as HTMLElement | undefined
    if (who) who.textContent = `${typingWho} is typing…`
    st.dots.forEach((d, k) => {
      const ph = (t * 2.4 - k * 0.18) % 1
      const a = 0.3 + 0.7 * Math.max(0, Math.sin(Math.PI * clamp(ph * 1.6)))
      d.style.opacity = a.toFixed(3)
      d.style.transform = `translateY(${(-2.5 * Math.max(0, Math.sin(Math.PI * clamp(ph * 1.6)))).toFixed(2)}px)`
    })
  }
  const sc = st.scroller
  const target = Math.max(0, sc.scrollHeight - sc.clientHeight - pending)
  if (Math.abs(sc.scrollTop - target) > 0.25) sc.scrollTop = target
}

/** rect (page px) of a scripted row's bubble, for cursor / camera aims */
export function rowRect(st: ChatState | null, i: number): [number, number, number, number] | null {
  const r = st?.rows[i]
  if (!r || r.el.style.display === 'none') return null
  const b = (r.el.querySelector('.rounded-2xl') as HTMLElement) ?? r.el
  const q = b.getBoundingClientRect()
  return [q.x, q.y, q.width, q.height]
}

export const typingProgress = (t: number, a: number, b: number) => ease.linear(prog(t, a, b))
