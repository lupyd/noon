#!/usr/bin/env node
// Dumps the stage's sound-effect cue list to out/cues.json.
import { writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { startServer } from './serve.mjs'
import { openStage } from './lib/capture.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const { server, url } = await startServer({ port: 4184 })
const st = await openStage(url, { scale: 0.25 })
try {
  // some cues depend on measured layout (e.g. scanner hits): run those scenes once
  const tl = await st.page.evaluate(() => window.__timeline)
  for (const s of tl.scenes.filter((x) => x.id === 'problem')) await st.page.evaluate((t) => window.__seek(t), s.start + 1)
  const cues = await st.page.evaluate(() => window.__cues)
  writeFileSync(path.join(ROOT, 'out', 'cues.json'), JSON.stringify(cues, null, 1))
  console.log(`${cues.length} cues → out/cues.json`)
} finally {
  await st.browser.close()
  server.close()
}
