#!/usr/bin/env node
// Deterministic, incremental renderer.
//
// The video is rendered per SCENE into cached chunks. A scene's cache key hashes
// everything that can change its pixels: the stage sources it uses (+ its two
// neighbours, which overlap it during transitions), the shared stage runtime,
// its timeline slice, the demo build and the output tier. Unchanged scenes are
// reused; changed ones are split into parts and rendered by a pool of
// persistent headless-Chromium workers (GPU raster, JPEG capture piped straight
// into h264_nvenc). Parts are concatenated with `-c copy`.
//
//   node scripts/render.mjs --draft     # 1280x720 @ 30 fps, NVENC p4 cq23   (iteration)
//   node scripts/render.mjs             # 1920x1080 @ 30 fps, NVENC p5 cq20
//   node scripts/render.mjs --final     # 1920x1080 @ 60 fps, NVENC p7 hq cq18 (YouTube)
//   options: --only chat,teams (force re-render) --from/--to <scene>  --workers N
//            --no-cache  --out file.mp4  --cpu-encode (libx264 veryfast)
//   env: STAGE_GPU=0 renders on SwiftShader (CPU) instead of the NVIDIA GPU.
import { spawn, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { startServer } from './serve.mjs'
import { openStage, track, untrack } from './lib/capture.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const OUT = path.join(ROOT, 'out')
const args = process.argv.slice(2)
const has = (n) => args.includes(`--${n}`)
const get = (n, d) => (has(n) ? args[args.indexOf(`--${n}`) + 1] : d)

const TIERS = {
  draft: { fps: 30, scale: 2 / 3, enc: ['-preset', 'p4', '-cq', '23'], name: 'draft' },
  default: { fps: 30, scale: 1, enc: ['-preset', 'p5', '-cq', '20'], name: 'default' },
  final: { fps: 60, scale: 1, enc: ['-preset', 'p7', '-tune', 'hq', '-rc', 'vbr', '-cq', '18'], name: 'final' },
}
const tier = has('final') ? TIERS.final : has('draft') || has('preview') ? TIERS.draft : TIERS.default
const fps = Number(get('fps', tier.fps))
const W = Math.round(1920 * tier.scale)
const H = Math.round(1080 * tier.scale)
const nvenc = !has('cpu-encode')
const encArgs = nvenc
  ? ['-c:v', 'h264_nvenc', ...tier.enc, '-b:v', '0', '-profile:v', 'high']
  : ['-c:v', 'libx264', '-preset', 'veryfast', '-crf', '20', '-profile:v', 'high']
const quality = Number(get('quality', 90))
// Size the pool from memory that is actually free right now (browser, editor, etc.
// already running), not total RAM. A worker decoding the 3K beat clips peaks near
// 1.8 GB, and 1.5 GB stays in reserve; oversubscribing here OOM-kills the session.
// measured peak ≈ 1.38 GB RSS per worker (GPU Chromium + display-size proxy clips)
const memWorkers = Math.max(1, Math.floor((os.freemem() - 1.5e9) / 1.4e9))
const workers = Number(get('workers', Math.min(6, memWorkers, os.cpus().length - 2)))
const port = Number(get('port', 4180))
const outFile = path.resolve(get('out', path.join(OUT, `video-${tier.name}.mp4`)))
const timeline = JSON.parse(readFileSync(path.join(OUT, 'timeline.json'), 'utf8'))

// ---------------------------------------------------------------- cache keys
const STAGE = path.join(ROOT, 'stage')
// v3: every scene kind lives in scenes/v3.ts; clip content is hashed into the timeline slice
const KIND_FILES = { logo: 'noon.ts', typecard: 'noon.ts', phone: 'noon.ts', blind: 'noon.ts' }
const SCENE_FILES = new Proxy({}, { get: () => 'v4.ts' })
const sha = (...parts) => {
  const h = createHash('sha1')
  for (const p of parts) h.update(typeof p === 'string' || Buffer.isBuffer(p) ? p : JSON.stringify(p))
  return h.digest('hex').slice(0, 12)
}
const fileHash = (f) => (existsSync(f) ? sha(readFileSync(f)) : 'none')
const walk = (d) => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]))
const sharedSrc = sha(
  ...walk(path.join(STAGE, 'src'))
    .filter((f) => !f.includes(`${path.sep}scenes${path.sep}`) || /(kit|index|v3|v4)\.ts$/.test(f))
    .sort()
    .map(fileHash),
  fileHash(path.join(STAGE, 'public', 'inject.js')),
  fileHash(path.join(STAGE, 'index.html'))
)
// the logo scenes read the traced SVG and the shared shader
const demoHash = sha(fileHash(path.join(ROOT, 'logo', 'noon-logo.svg')), fileHash(path.join(ROOT, 'logo', 'engine.js')))
const sceneKey = (i) => {
  const s = timeline.scenes[i]
  const near = [i - 1, i, i + 1].map((k) => timeline.scenes[k]).filter(Boolean)
  return sha(
    tier, fps, quality, nvenc, sharedSrc, demoHash,
    near.map((n, k) => [n.id, n.kind, k === 1 || near.length === 2 && n === s ? 0 : n.start - s.start, +(n.end - n.start).toFixed(4), n.lines.map((l) => [l.id, +(l.start - n.start).toFixed(4), +(l.end - n.start).toFixed(4)]), n.beat?.hash ?? null, n.beat?.in ?? null, n.beat?.out ?? null, n.cards ?? null, n.mode ?? null, n.message ?? null, n.beat?.speed ?? null, fileHash(path.join(STAGE, 'src', 'scenes', KIND_FILES[n.kind] ?? 'v4.ts'))]),
    s.id === timeline.scenes.at(-1).id ? timeline.duration : 0
  )
}

// ---------------------------------------------------------------- plan
const pick = (v) => (v === undefined ? null : timeline.scenes.findIndex((s) => s.id === v))
const fromIdx = pick(get('from')) ?? 0
const toIdx = pick(get('to')) ?? timeline.scenes.length - 1
const force = new Set((get('only', '') || '').split(',').filter(Boolean))
const CACHE = path.join(ROOT, '.cache', 'scenes', tier.name)
mkdirSync(CACHE, { recursive: true })
const plan = []
for (let i = fromIdx; i <= toIdx; i++) {
  const s = timeline.scenes[i]
  const f0 = Math.round(s.start * fps)
  const f1 = Math.round(s.end * fps)
  const key = sceneKey(i)
  const dir = path.join(CACHE, `${s.id}.${key}`)
  const ok = path.join(dir, 'ok.json')
  const cached = !has('no-cache') && !force.has(s.id) && existsSync(ok)
  plan.push({ i, id: s.id, f0, f1, key, dir, ok, cached })
}
const todo = plan.filter((p) => !p.cached)
const todoFrames = todo.reduce((a, p) => a + p.f1 - p.f0, 0)
// part size: enough parts to keep every worker busy, few enough to amortise app mounts
const partTarget = Math.max(fps * 2, Math.ceil(todoFrames / (workers * 1.6)))
const jobs = []
for (const p of todo) {
  rmSync(p.dir, { recursive: true, force: true })
  mkdirSync(p.dir, { recursive: true })
  const n = p.f1 - p.f0
  const parts = Math.max(1, Math.round(n / partTarget))
  p.parts = []
  for (let k = 0; k < parts; k++) {
    const a = p.f0 + Math.floor((n * k) / parts)
    const b = p.f0 + Math.floor((n * (k + 1)) / parts)
    const file = path.join(p.dir, `p${String(k).padStart(2, '0')}.mp4`)
    p.parts.push(file)
    jobs.push({ scene: p.id, a, b, file })
  }
}
// longest-first keeps the tail short; then by time for frame locality
jobs.sort((x, y) => y.b - y.a - (x.b - x.a) || x.a - y.a)

console.log(`${tier.name}: ${W}x${H} @ ${fps} fps · ${nvenc ? 'h264_nvenc' : 'libx264'} · ${workers} workers`)
console.log(`scenes: ${plan.map((p) => (p.cached ? `${p.id}✓` : `${p.id}*`)).join(' ')}  (✓ cached, * render)`)

const countFrames = (file) => {
  const r = spawnSync('ffprobe', ['-v', 'error', '-count_packets', '-select_streams', 'v:0', '-show_entries', 'stream=nb_read_packets', '-of', 'csv=p=0', file], { encoding: 'utf8' })
  return parseInt((r.stdout || '').trim(), 10) || 0
}

// ---------------------------------------------------------------- workers
const t0 = Date.now()
let done = 0
let lastLog = 0
const prof = { seek: 0, shot: 0, write: 0, n: 0 }
const report = (force = false) => {
  if (!force && Date.now() - lastLog < 4000) return
  lastLog = Date.now()
  const el = (Date.now() - t0) / 1000
  process.stdout.write(`  ${done}/${todoFrames} frames · ${(done / el).toFixed(1)} fps · ${el.toFixed(0)}s\n`)
}

async function encodeJob(st, job) {
  const tmp = job.file + '.part.mp4'
  const ff = track(
    spawn('ffmpeg', [
      '-hide_banner', '-loglevel', 'error', '-y',
      '-f', 'image2pipe', '-framerate', String(fps), '-c:v', 'mjpeg', '-i', '-',
      // JPEG frames decode as full-range yuvj420p: convert to limited-range yuv420p for players
      '-vf', 'scale=in_range=full:out_range=tv,format=yuv420p', '-color_range', 'tv',
      ...encArgs, '-pix_fmt', 'yuv420p', '-g', String(fps * 2), '-bf', '0',
      '-color_primaries', 'bt709', '-color_trc', 'bt709', '-colorspace', 'bt709',
      tmp,
    ], { stdio: ['pipe', 'inherit', 'inherit'] })
  )
  let ffErr = null
  ff.stdin.on('error', (e) => (ffErr = e))
  const closed = new Promise((res) => ff.on('close', (c) => (untrack(ff), res(c))))
  try {
    for (let i = job.a; i < job.b; i++) {
      const a = performance.now()
      await st.seek(i / fps)
      const b = performance.now()
      const buf = await st.shot('jpeg', quality)
      const c = performance.now()
      if (ffErr) throw ffErr
      if (!ff.stdin.write(buf)) await new Promise((r) => ff.stdin.once('drain', r))
      prof.seek += b - a
      prof.shot += c - b
      prof.write += performance.now() - c
      prof.n++
      done++
      report()
    }
  } finally {
    ff.stdin.end()
  }
  const code = await closed
  if (code !== 0) throw new Error(`ffmpeg exited ${code}`)
  const got = countFrames(tmp)
  if (got !== job.b - job.a) throw new Error(`${job.scene}: expected ${job.b - job.a} frames, got ${got}`)
  renameSync(tmp, job.file)
}

const { server, url } = await startServer({ port })
const browsers = new Set()
try {
  if (jobs.length) {
    const queue = [...jobs]
    let renderer = ''
    await Promise.all(
      Array.from({ length: Math.min(workers, jobs.length) }, async () => {
        let st = await openStage(url, { scale: tier.scale, query: tier.name === 'draft' ? '?q=draft' : '' })
        browsers.add(st.browser)
        renderer ||= st.renderer
        while (queue.length) {
          const job = queue.shift()
          for (let attempt = 1; ; attempt++) {
            try {
              await encodeJob(st, job)
              break
            } catch (e) {
              if (attempt >= 3) throw e
              console.error(`  ${job.scene} [${job.a},${job.b}) failed (${e.message}); retry ${attempt}`)
              await st.browser.close().catch(() => {})
              browsers.delete(st.browser)
              st = await openStage(url, { scale: tier.scale, query: tier.name === 'draft' ? '?q=draft' : '' })
              browsers.add(st.browser)
            }
          }
        }
        await st.browser.close().catch(() => {})
        browsers.delete(st.browser)
      })
    )
    report(true)
    console.log(`  gpu: ${renderer}`)
    if (prof.n) console.log(`  per frame: seek ${(prof.seek / prof.n).toFixed(1)} ms · capture ${(prof.shot / prof.n).toFixed(1)} ms · encoder write ${(prof.write / prof.n).toFixed(1)} ms (per worker)`)
    for (const p of todo) writeFileSync(p.ok, JSON.stringify({ key: p.key, frames: p.f1 - p.f0, parts: p.parts.map((f) => path.basename(f)) }))
  }
  // ---------------------------------------------------------------- concat
  const list = path.join(CACHE, 'concat.txt')
  const files = plan.flatMap((p) => JSON.parse(readFileSync(p.ok, 'utf8')).parts.map((f) => path.join(p.dir, f)))
  writeFileSync(list, files.map((f) => `file '${f}'`).join('\n'))
  mkdirSync(path.dirname(outFile), { recursive: true })
  const r = spawnSync('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-y', '-f', 'concat', '-safe', '0', '-i', list, '-c', 'copy', '-movflags', '+faststart', outFile], { stdio: 'inherit' })
  if (r.status !== 0) throw new Error('concat failed')
  const secs = (Date.now() - t0) / 1000
  const frames = plan.reduce((a, p) => a + p.f1 - p.f0, 0)
  console.log(`wrote ${outFile} (${frames} frames, ${todoFrames} rendered) in ${secs.toFixed(1)}s${todoFrames ? ` · ${(todoFrames / secs).toFixed(1)} fps` : ''}`)
  writeFileSync(path.join(OUT, `render-${tier.name}.json`), JSON.stringify({ tier: tier.name, fps, size: [W, H], workers, frames, rendered: todoFrames, seconds: +secs.toFixed(1), scenes: plan.map((p) => ({ id: p.id, cached: p.cached })), out: outFile }, null, 2))
  // prune stale cache dirs for this tier
  const keep = new Set(plan.map((p) => path.basename(p.dir)))
  const ids = new Set(plan.map((p) => p.id))
  for (const d of readdirSync(CACHE)) {
    const id = d.split('.')[0]
    if (ids.has(id) && !keep.has(d) && statSync(path.join(CACHE, d)).isDirectory()) rmSync(path.join(CACHE, d), { recursive: true, force: true })
  }
} finally {
  await Promise.all([...browsers].map((b) => b.close().catch(() => {})))
  server.close()
}
