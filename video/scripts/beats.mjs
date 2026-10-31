// Beat scripts for scripts/record.mjs. Each beat drives the REAL Noon app (real
// frontend, real API in emulator mode) with real mouse moves, clicks and keys.
// Data comes from scripts/seed.ts through the real API.
// `focus` names the ONE action the camera may push in on (DIRECTION.md):
//   { on: <action name>, until: <action name> } — rect of `on`, held until `until`.
//
// Order matters: create makes "Q3 Team Pulse", respond answers it, results reads it.
//   bun scripts/seed.ts reset && node scripts/record.mjs create respond results
import { spawnSync } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const seed = (...args) => {
  const r = spawnSync('bun', ['scripts/seed.ts', ...args], { cwd: ROOT, encoding: 'utf8' })
  if (r.status !== 0) throw new Error(`seed ${args.join(' ')}: ${r.stderr}`)
  return r.stdout.trim()
}
const OWNER = 'maya@lupyd.com'
const ownerAuth = () => ({ theme: 'light', noon_verified_email: OWNER, noon_email_token: seed('token', OWNER) })

export const FORM = 'Q3 Team Pulse'
export const RESPONDENT = 'priya.raman@lupyd.com'
/** what Priya writes, and what the blind beat carries */
export const ANSWER = 'Release freezes keep getting extended, and nobody says why.'

const settle = async (rec, ms = 600) => {
  await rec.page.waitForNetworkIdle({ idleTime: 250, timeout: 6000 }).catch(() => {})
  await rec.sleep(ms)
}

export const BEATS = {
  // 3 · Create: dashboard → Templates → Team Pulse Check → name it, paste the team, create, copy the link
  create: {
    // a re-take starts from a clean dashboard
    route: async () => (seed('drop', FORM), '/dashboard'),
    auth: ownerAuth,
    cursorStart: { x: 980, y: 520 },
    focus: { on: 'whitelist', until: 'pasted' },
    async run(rec) {
      await rec.sleep(500)
      await rec.click({ sel: 'a', text: /^Templates$/ }, { name: 'templates', after: 250 })
      await settle(rec, 500)
      await rec.click({ sel: 'button', text: /Use template/, row: /Team Pulse Check/ }, { name: 'use-template', after: 300 })
      await settle(rec, 500)
      await rec.click("input[placeholder^='e.g. Q2']", { name: 'name', fx: 0.25, after: 120 })
      await rec.page.keyboard.down('Control')
      await rec.page.keyboard.press('a')
      await rec.page.keyboard.up('Control')
      await rec.type("input[placeholder^='e.g. Q2']", FORM, { name: 'type-name', cps: 16, after: 300 })
      await rec.click("[placeholder^='team@company.com']", { name: 'whitelist', fx: 0.3, after: 250 })
      await rec.paste("[placeholder^='team@company.com']", seed('team').split('\n').join(', '), { name: 'pasted', after: 1300 })
      await rec.click({ sel: 'button', text: /^Create Form$/ }, { name: 'create', after: 300 })
      await settle(rec, 700)
      await rec.click("button[title='Copy Link']", { name: 'copy', after: 1400 })
    },
  },

  // 4 · Respond: Priya on her phone — email, one-time code, three taps and a sentence, submit
  respond: {
    route: async () => `/forms/${seed('id', FORM)}`,
    viewport: { width: 390, height: 800, dpr: 2, mobile: true }, // Pixel 9 Pro opening minus status bar (52) and gesture inset (18)
    cursorStart: { x: 200, y: 560 },
    settle: 1200,
    async run(rec) {
      await rec.click("input[placeholder='name@company.com']", { name: 'email', after: 100 })
      await rec.type("input[placeholder='name@company.com']", RESPONDENT, { name: 'type-email', cps: 22, after: 200 })
      await rec.click({ sel: 'button[type=submit]', text: /./ }, { name: 'send-code', after: 300 })
      await settle(rec, 400)
      await rec.click("input[placeholder='000000']", { name: 'code', after: 100 })
      await rec.type("input[placeholder='000000']", '123456', { name: 'type-code', cps: 9, after: 200 })
      await rec.click({ sel: 'button[type=submit]', text: /./ }, { name: 'verify', after: 300 })
      await settle(rec, 700)
      await rec.click({ sel: 'label', text: /^4 - Great$/ }, { name: 'morale', after: 250 })
      await rec.click({ sel: 'label', text: /^I am overwhelmed$/ }, { name: 'workload', after: 250 })
      await rec.click({ sel: 'label', text: /^2 - Subpar$/ }, { name: 'communication', after: 250 })
      await rec.click("[placeholder='Describe blockers...']", { name: 'blocker', after: 100 })
      await rec.type("[placeholder='Describe blockers...']", ANSWER, { name: 'type-answer', cps: 24, after: 400 })
      await rec.click({ sel: 'button[type=submit]', text: /./ }, { name: 'submit', after: 300 })
      await settle(rec, 200)
      await rec.rect({ sel: 'h2', text: /Data Transmitted/ }, 'sent')
      await rec.sleep(1300)
    },
  },

  // 6 · Results: the answers, then who verified (decoupled), then the charts
  results: {
    // the rest of the team answers through the same anonymous flow before the take
    route: async () => (seed('fill', FORM, RESPONDENT), `/forms/${seed('id', FORM)}/results`),
    auth: ownerAuth,
    cursorStart: { x: 1100, y: 520 },
    focus: { on: 'decoupled', until: 'decoupled-hold' },
    async run(rec) {
      await rec.sleep(900)
      await rec.scroll(560, 1500)
      await rec.sleep(300)
      await rec.rect({ sel: 'p', text: /cryptographically decoupled/ }, 'decoupled')
      await rec.sleep(1900)
      rec.mark('decoupled-hold')
      await rec.scroll('top', 900)
      await rec.click({ sel: 'button', text: /Analytics & Charts/ }, { name: 'analytics', after: 900 })
      await rec.scroll(520, 1700)
      await rec.sleep(900)
    },
  },
}
