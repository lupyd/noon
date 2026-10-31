import type { SceneBuilder } from '../types'
import { blind, logoScene, phoneScene, statement } from './noon'
import { clip } from './v4'

// scenes are chosen by `kind` in out/timeline.json (scripts/timeline.mjs SHOTS)
export const SCENES: Record<string, SceneBuilder> = { logo: logoScene, typecard: statement, clip, phone: phoneScene, blind }
