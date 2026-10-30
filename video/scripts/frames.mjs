#!/usr/bin/env node
// Capture stills at given times for review: node scripts/frames.mjs 1.5 10 22.3 [--scale 0.5] [--out dir]
import { mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { startServer } from './serve.mjs'
import { openStage } from './lib/capture.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const args = process.argv.slice(2)
const get = (n, d) => (args.includes(`--${n}`) ? args[args.indexOf(`--${n}`) + 1] : d)
const scale = Number(get('scale', 0.5))
const out = get('out', path.join(ROOT, 'out', 'stills'))
const port = Number(get('port', 4182))
const times = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--'))).map(Number)
mkdirSync(out, { recursive: true })
const { server, url } = await startServer({ port })
const st = await openStage(url, { scale, log: !!process.env.LOG })
try {
  for (const t of times) {
    const t0 = Date.now()
    await st.seek(t)
    const buf = await st.shot('png')
    const f = path.join(out, `t${t.toFixed(2).padStart(6, '0')}.png`)
    writeFileSync(f, buf)
    console.log(`${f}  (${Date.now() - t0}ms)`)
  }
} finally {
  await st.browser.close()
  server.close()
}
