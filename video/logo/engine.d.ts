export const LOGO: number
export const CONTENT_C: [number, number]
export const CONTENT_H: number
export const NAVY: string
export interface NoonLogo {
  suns: { c: [number, number]; r: number; rim: number }[]
  draw(p: { t: number; amp: number; angle: number; rect: number[] }): void
}
export function createLogo(canvas: HTMLCanvasElement, opts: { svgUrl: string; tex?: number; starTex?: number; detail?: number }): Promise<NoonLogo>
