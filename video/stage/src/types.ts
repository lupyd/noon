export interface Line {
  id: string
  start: number
  end: number
  dur: number
  text: string
  caption: string
}
export interface SceneT {
  id: string
  start: number
  end: number
  bars: number
  endCard: number
  lines: Line[]
}
export interface Timeline {
  bpm: number
  beat: number
  bar: number
  duration: number
  scenes: SceneT[]
}
export interface SceneAPI {
  root: HTMLElement
  s: SceneT
  tl: Timeline
  /** scene length in seconds */
  dur: number
  /** a VO line's start/end relative to the scene start */
  L: (id: string) => { start: number; end: number }
  beat: number
  bar: number
}
/** returns an update(localTime, globalTime) function */
export type SceneBuilder = (api: SceneAPI) => (lt: number, t: number) => void
