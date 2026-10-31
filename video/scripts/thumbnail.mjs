#!/usr/bin/env node
// Renders the 1280x720 YouTube thumbnail (stage ?thumb mode) to out/thumbnail.png
import { writeFileSync, rmSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { startServer } from './serve.mjs'
import { openStage } from './lib/capture.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const { server, url } = await startServer({ port: 4185 })
const st = await openStage(url, { scale: 2 / 3, query: '?thumb=1' })
try {
  await st.seek(10)
  const file = path.join(ROOT, 'out', 'thumbnail.png')
  const raw = path.join(ROOT, '.cache', 'thumbnail-raw.png')
  writeFileSync(raw, await st.shot('png'))
  // capture is 1920x1080; YouTube thumbnails are 1280x720
  const r = spawnSync('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-y', '-i', raw, '-vf', 'scale=1280:720:flags=lanczos', file])
  if (r.status !== 0) throw new Error('ffmpeg scale failed')
  rmSync(raw, { force: true })
  console.log(`wrote ${file}`)
} finally {
  await st.browser.close()
  server.close()
}
