#!/usr/bin/env node
// Display-size proxies of the 2× beat recordings: beats/<id>.proxy.mp4 at the
// on-screen window size (1536 wide; phones 1x of their 2× capture height).
// The stage plays proxies everywhere except camera push-ins at 1080p tiers, so
// render workers decode ~4× fewer pixels. Rebuilt only when the source changes.
import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const DIR = path.join(ROOT, 'beats')
for (const f of readdirSync(DIR).filter((x) => x.endsWith('.mp4') && !x.endsWith('.proxy.mp4'))) {
  const src = path.join(DIR, f)
  const dst = src.replace(/\.mp4$/, '.proxy.mp4')
  if (existsSync(dst) && statSync(dst).mtimeMs > statSync(src).mtimeMs) continue
  const meta = JSON.parse(readFileSync(src.replace(/\.mp4$/, '.json'), 'utf8'))
  const w = meta.viewport.mobile ? meta.viewport.width * 2 : 1536
  const r = spawnSync('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-y', '-i', src, '-vf', `scale=${w}:-2:flags=lanczos`, '-c:v', 'h264_nvenc', '-preset', 'p5', '-cq', '18', '-b:v', '0', '-g', '2', '-bf', '0', '-pix_fmt', 'yuv420p', '-movflags', '+faststart', dst], { stdio: 'inherit' })
  if (r.status !== 0) throw new Error(`proxy ${f} failed`)
  console.log(`proxy ${path.basename(dst)}`)
}
