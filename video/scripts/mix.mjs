#!/usr/bin/env node
// Final audio mix + mux.
//   VO lines placed at their timeline positions (adelay), lightly EQ'd/compressed
//   music ducked under the VO (sidechaincompress keyed by the VO bus)
//   SFX bus on top, then two-pass EBU R128 loudnorm to -14 LUFS / -1 dBTP
//   AAC 320k muxed with the rendered video.
//
//   node scripts/mix.mjs [--video out/video.mp4] [--music path/to/track.mp3]
//                        [--music-gain -2] [--out out/noon-showcase.mp4] [--no-sfx]
import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync, copyFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const OUT = path.join(ROOT, 'out')
const args = process.argv.slice(2)
const has = (n) => args.includes(`--${n}`)
const get = (n, d) => (has(n) ? args[args.indexOf(`--${n}`) + 1] : d)

const tl = JSON.parse(readFileSync(path.join(OUT, 'timeline.json'), 'utf8'))
const D = tl.duration
const video = path.resolve(get('video', existsSync(path.join(OUT, 'video.mp4')) ? path.join(OUT, 'video.mp4') : path.join(OUT, 'video-preview.mp4')))
const music = path.resolve(get('music', path.join(OUT, 'music', 'music.wav')))
const musicOverride = has('music')
const musicGainDb = Number(get("music-gain", musicOverride ? -6 : -3))
const outFile = path.resolve(get('out', path.join(OUT, 'noon-showcase.mp4')))
const sfx = path.join(OUT, 'sfx', 'sfx.wav')
const useSfx = !has('no-sfx') && existsSync(sfx)

const run = (cmd, a, opts = {}) => {
  const r = spawnSync(cmd, a, { encoding: 'utf8', maxBuffer: 1 << 26, ...opts })
  if (r.status !== 0) {
    console.error(r.stderr?.slice(-4000))
    throw new Error(`${cmd} failed`)
  }
  return r
}

// --- inputs
const lines = tl.scenes.flatMap((s) => s.lines)
const inputs = []
const add = (f) => (inputs.push(f), inputs.length - 1)
const iMusic = add(music)
const iSfx = useSfx ? add(sfx) : -1
const voIdx = lines.map((l) => {
  const f = path.join(OUT, 'vo', `${l.id}.wav`)
  if (!existsSync(f)) throw new Error(`missing VO ${f} (run pnpm vo)`)
  return { l, i: add(f) }
})

// overlap check
const sorted = [...lines].sort((a, b) => a.start - b.start)
for (let k = 1; k < sorted.length; k++) if (sorted[k].start < sorted[k - 1].end - 1e-3) throw new Error(`VO overlap: ${sorted[k - 1].id} / ${sorted[k].id}`)

const f = []
// VO bus: each line resampled to 48k stereo, delayed into place
voIdx.forEach(({ l, i }, k) => {
  const ms = Math.round(l.start * 1000)
  f.push(`[${i}:a]aresample=48000,aformat=channel_layouts=stereo,adelay=${ms}|${ms}[v${k}]`)
})
f.push(`${voIdx.map((_, k) => `[v${k}]`).join('')}amix=inputs=${voIdx.length}:normalize=0:dropout_transition=0,apad=whole_dur=${D},atrim=0:${D},` +
  // warm, present VO: rumble cut, gentle low-mid dip, presence lift, de-harsh, glue comp
  `highpass=f=75,equalizer=f=280:t=q:w=1.2:g=-2,equalizer=f=3200:t=q:w=1.4:g=2.5,equalizer=f=7500:t=q:w=2:g=-1.5,` +
  `acompressor=threshold=0.12:ratio=3:attack=8:release=180:makeup=1.6,volume=5dB,asplit=2[vo][vokey]`)
// music: trim/pad/fade to the timeline, ducked by VO
const mfade = musicOverride ? `,afade=t=out:st=${(D - 4).toFixed(2)}:d=4` : ''
f.push(`[${iMusic}:a]aresample=48000,aformat=channel_layouts=stereo,atrim=0:${D},apad=whole_dur=${D}${mfade},volume=${musicGainDb}dB[m0]`)
f.push(`[m0][vokey]sidechaincompress=threshold=0.035:ratio=5:attack=25:release=420:makeup=1:knee=4[mduck]`)
let bus = '[mduck][vo]'
let n = 2
if (useSfx) {
  f.push(`[${iSfx}:a]aresample=48000,aformat=channel_layouts=stereo,atrim=0:${D},apad=whole_dur=${D},volume=-3dB[sfx]`)
  bus += '[sfx]'
  n = 3
}
f.push(`${bus}amix=inputs=${n}:normalize=0:dropout_transition=0,atrim=0:${D}[pre]`)

const graph = f.join(';\n')
const pre = path.join(ROOT, '.cache', 'mix-pre.wav')
const inArgs = inputs.flatMap((x) => ['-i', x])
console.log('mixing…')
run('ffmpeg', ['-hide_banner', '-y', ...inArgs, '-filter_complex', graph, '-map', '[pre]', '-c:a', 'pcm_f32le', '-ar', '48000', pre])

// --- two-pass loudnorm
const m = run('ffmpeg', ['-hide_banner', '-i', pre, '-af', 'loudnorm=I=-14:TP=-1:LRA=11:print_format=json', '-f', 'null', '-'])
const js = JSON.parse(m.stderr.slice(m.stderr.lastIndexOf('{'), m.stderr.lastIndexOf('}') + 1))
const norm = `loudnorm=I=-14:TP=-1:LRA=11:measured_I=${js.input_i}:measured_TP=${js.input_tp}:measured_LRA=${js.input_lra}:measured_thresh=${js.input_thresh}:offset=${js.target_offset}:linear=true:print_format=summary`
const finalWav = path.join(OUT, 'noon-showcase-audio.wav')
// loudnorm upsamples internally; a final limiter guards true peak after resampling
run('ffmpeg', ['-hide_banner', '-y', '-i', pre, '-af', `${norm},aresample=48000,alimiter=limit=0.87:attack=2:release=60:level=false`, '-c:a', 'pcm_s24le', '-ar', '48000', finalWav])

// --- mux
if (existsSync(video)) {
  run('ffmpeg', ['-hide_banner', '-y', '-i', video, '-i', finalWav, '-map', '0:v:0', '-map', '1:a:0', '-c:v', 'copy', '-c:a', 'aac', '-b:a', '320k', '-ar', '48000', '-shortest', '-movflags', '+faststart', outFile])
  console.log(`wrote ${outFile}`)
} else console.warn(`no video at ${video}; wrote audio only: ${finalWav}`)

// --- report
const r = run('ffmpeg', ['-hide_banner', '-i', finalWav, '-af', 'ebur128=peak=true', '-f', 'null', '-'])
const tail = r.stderr.slice(r.stderr.lastIndexOf('Summary:'))
console.log(tail.trim())
// subtitles are produced separately from the final mix (aligned), never copied here
writeFileSync(path.join(OUT, 'mix-report.txt'), `${new Date().toISOString()}\nvideo: ${video}\nmusic: ${music}${musicOverride ? ' (override)' : ''}\n\n${tail}\n`)
