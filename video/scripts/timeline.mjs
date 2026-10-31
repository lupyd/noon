#!/usr/bin/env node
// v3 timeline (DIRECTION.md): the shot list below, in order. Clip scenes take
// their length from the recorded beat (beats/<id>.json), trimmed to the action;
// type/brand cards take theirs from their VO line. Each VO line is placed at its
// scene start + lead. Writes out/timeline.json (+ a rough .srt from line slots;
// the shipped .srt is aligned from the final mix separately).
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const OUT = path.join(ROOT, 'out')
mkdirSync(OUT, { recursive: true })
export const BPM = 96

// Noon showcase (DIRECTION.md). kind: logo | typecard | clip | phone | blind (stage/src/scenes).
// vo: line ids (placed lead → gap → …; `at` pins a line to a scene time). trim: [s before first
// action, s after last action | null = to clip end]. speed: [[clip t, rate], …] speed ramps over
// the recording (rate holds until the next breakpoint). Lengths snap UP to whole beats.
const ANSWER = 'Release freezes keep getting extended, and nobody says why.'
export const SHOTS = [
  { id: 'intro', kind: 'logo', mode: 'intro', vo: ['intro1', 'intro2'], lead: 0.7, at: { intro2: 4.75 }, tail: 0.9, min: 7 },
  { id: 'problem', kind: 'typecard', cards: ['“Anonymous” forms\nstill know who you are.'], vo: ['problem'], lead: 0.35, tail: 0.6, min: 4.5 },
  { id: 'create', kind: 'clip', beat: 'create', vo: ['create'], trim: [1.3, 1.1], title: 'Create.', speed: [[0, 1.5], [7.9, 1], [10.2, 1.6]] },
  { id: 'respond', kind: 'phone', beat: 'respond', vo: ['respond'], trim: [0.4, 1.0], title: 'Respond.', speed: [[0, 2.2], [9.2, 1.15], [13.0, 1.8], [16.6, 1]] },
  { id: 'blind', kind: 'blind', vo: ['blind1', 'blind2'], lead: 0.7, gap: 0.55, tail: 0.9, min: 9, message: ANSWER, email: 'priya.raman@lupyd.com' },
  { id: 'results', kind: 'clip', beat: 'results', vo: ['results'], trim: [0.5, 0.6], title: 'Results.', speed: [[0, 1.3], [3.4, 1], [6.1, 1.5]] },
  { id: 'cta', kind: 'logo', mode: 'outro', vo: ['cta1', 'cta2'], lead: 1.3, gap: 0.45, tail: 1.2, min: 6.5 },
]
/** stage seconds to play clip span [a, b] under a speed map */
export function mappedDur(speed, a, b) {
  if (!speed) return b - a
  let d = 0
  for (let i = 0; i < speed.length; i++) {
    const lo = Math.max(a, speed[i][0])
    const hi = Math.min(b, speed[i + 1]?.[0] ?? Infinity)
    if (hi > lo) d += (hi - lo) / speed[i][1]
  }
  return d
}
const TITLE_OFF = 0.95 // stage TITLE.done - 0.1
const LEAD = { clip: 0.3, phone: 0.3 }

const script = JSON.parse(readFileSync(path.join(ROOT, 'vo', 'script.json'), 'utf8'))
const durPath = path.join(OUT, 'vo', 'durations.json')
const measured = existsSync(durPath) ? JSON.parse(readFileSync(durPath, 'utf8')).lines : {}
const estimate = (text) => Math.max(0.6, text.split(/\s+/).length / 2.7)
const frame = (x) => Math.round(x * 60) / 60
const hashFile = (f) => createHash('sha1').update(readFileSync(f)).digest('hex').slice(0, 10)

const beatMeta = async (id, shot) => {
  const jf = path.join(ROOT, 'beats', `${id}.json`)
  const mf = path.join(ROOT, 'beats', `${id}.mp4`)
  if (!existsSync(jf) || !existsSync(mf)) throw new Error(`beat ${id} not recorded (node scripts/record.mjs ${id})`)
  const m = JSON.parse(readFileSync(jf, 'utf8'))
  const first = Math.min(...m.actions.map((a) => a.t), m.duration)
  const lastAct = Math.max(...m.actions.map((a) => a.end ?? a.t), 0)
  const [pre, post] = shot?.trim ?? [0.3, 0.6]
  const a = Math.max(0, first - pre)
  const b = post === null ? m.duration - 0.3 : Math.min(m.duration - 0.05, lastAct + post)
  const pop = (await import('./beats.mjs')).BEATS[id]?.pop
  const pf = path.join(ROOT, 'beats', `${id}.proxy.mp4`)
  if (!existsSync(pf)) throw new Error(`no proxy for ${id} (node scripts/proxies.mjs)`)
  const out = { ...m, pop, in: +a.toFixed(3), out: +b.toFixed(3), src: `/__beats/${id}.mp4?h=${hashFile(mf)}`, proxy: `/__beats/${id}.proxy.mp4?h=${hashFile(pf)}`, hash: hashFile(jf) + hashFile(mf) }
  delete out.recordedAt
  return out
}

let cursor = 0
const scenes = []
const SNAP = 60 / BPM // cuts land on the beat
for (const shot of SHOTS) {
  const lines = (shot.vo ?? []).map((id) => {
    const l = script.lines.find((x) => x.id === id)
    if (!l) throw new Error(`no VO line ${id}`)
    return l
  })
  const s = { id: shot.id, kind: shot.kind }
  for (const k of ['message', 'title', 'enter', 'exit', 'mode', 'cards', 'email']) if (shot[k]) s[k] = shot[k]
  let clipDur = 0
  if (shot.beat) {
    s.beat = await beatMeta(shot.beat, shot)
    if (shot.speed) s.beat.speed = shot.speed
    if (!shot.still) clipDur = mappedDur(shot.speed, s.beat.in, s.beat.out) + (shot.title ? TITLE_OFF : 0)
  }
  if (shot.cuts) s.cuts = await Promise.all(shot.cuts.map(async ([id, act, z, dt]) => {
    const m = await beatMeta(id, [0, null])
    const a = m.actions.find((x) => x.name === act)
    return { beat: m, t: Math.max(0, (a?.t ?? 1) + dt), rect: a?.rect, z }
  }))
  if (shot.desk) s.desk = await beatMeta(shot.desk, null)
  if (shot.phone) s.phone = await beatMeta(shot.phone, [0, null])
  const lead = (shot.lead ?? LEAD[shot.kind] ?? 0.3) + (shot.title ? TITLE_OFF : 0)
  let t = lead
  const placed = lines.map((l, i) => {
    if (i > 0) t += shot.gap ?? 0.4
    if (shot.at?.[l.id] !== undefined) t = shot.at[l.id]
    const dur = measured[l.id] ?? estimate(l.text)
    const st = t
    t += dur
    return { id: l.id, st, en: t, dur, text: l.text, caption: l.caption ?? l.text, estimated: !(l.id in measured) }
  })
  let dur = Math.max(clipDur, lines.length ? t + (shot.tail ?? 0.3) : 0, shot.min ?? 0)
  dur = Math.ceil((dur + (shot.endCard ?? 0)) / SNAP - 1e-6) * SNAP
  if (s.beat && !shot.still && !shot.speed) s.beat.out = +Math.min(s.beat.in + dur - (shot.title ? TITLE_OFF : 0), s.beat.duration - 0.05).toFixed(3)
  s.start = +cursor.toFixed(4)
  s.end = +(cursor + dur).toFixed(4)
  s.endCard = shot.endCard ?? 0
  s.lines = placed.map((l) => ({ id: l.id, start: +(cursor + l.st).toFixed(4), end: +(cursor + l.en).toFixed(4), dur: l.dur, text: l.text, caption: l.caption, estimated: l.estimated }))
  scenes.push(s)
  cursor += dur
}

// experiments: EXP=name1,name2 enables stage/timeline variants (showcase-experiments branch)
const EXP = (process.env.EXP || '').split(',').filter(Boolean)
const timeline = { v: 5, exp: EXP, bpm: BPM, beat: 60 / BPM, bar: 240 / BPM, duration: +cursor.toFixed(4), scenes, generatedAt: new Date().toISOString() }
writeFileSync(path.join(OUT, 'timeline.json'), JSON.stringify(timeline, null, 1))
console.log(
  scenes.map((s) => `${s.id.padEnd(12)} ${s.start.toFixed(2).padStart(6)} → ${s.end.toFixed(2).padStart(6)}  (${(s.end - s.start).toFixed(2)}s)${s.lines[0] ? `  vo ${s.lines[0].dur.toFixed(2)}s${s.lines[0].estimated ? ' (est)' : ''}` : ''}`).join('\n') +
    `\nTotal ${timeline.duration.toFixed(2)}s`
)
