// Sound-effect cues registered by scenes at build time (absolute seconds).
// scripts/cues.mjs dumps them to out/cues.json; music/sfx.py renders them.
export interface Cue {
  t: number
  kind: string
  gain: number
}
export const CUES: Cue[] = []
export const cue = (t: number, kind: string, gain = 1) => {
  if (isFinite(t)) CUES.push({ t: +t.toFixed(4), kind, gain })
}
