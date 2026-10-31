#!/usr/bin/env node
// Subtitles from the timeline: each VO line is placed at an exact, measured time
// (scripts/timeline.mjs), so its slot is its caption. → out/noon-showcase.srt
import { readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const OUT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'out')
const tl = JSON.parse(readFileSync(path.join(OUT, 'timeline.json'), 'utf8'))
const ts = (s) => new Date(Math.round(s * 1000)).toISOString().slice(11, 23).replace('.', ',')
const cues = tl.scenes.flatMap((s) => s.lines).map((l, i) => `${i + 1}\n${ts(l.start)} --> ${ts(l.end + 0.15)}\n${l.caption}\n`)
writeFileSync(path.join(OUT, 'noon-showcase.srt'), cues.join('\n'))
console.log(`${cues.length} captions → out/noon-showcase.srt`)
