// Demo data for the showcase, written through Noon's real API (local emulator
// stack only: EMULATOR_MODE=true fixes every OTP to 123456).
//
//   bun scripts/seed.ts reset              wipe the local DB, give the owner a Team
//                                          plan, create the background forms + responses
//   bun scripts/seed.ts fill "<form name>" fill the newest form with that name from its
//                                          whitelist, through the anonymous blind-signature
//                                          flow (each respondent verifies by OTP first)
//
// Every response goes through the same protocol as the browser: hash the
// encoded submission with a nonce, blind it, have the server sign it with the
// respondent's token, unblind, submit without any identity.
import { spawnSync } from 'node:child_process'
import { TEMPLATES } from '../../frontend/src/components/templates.ts'
import * as mycrypto from '../../frontend/src/crypto.ts'
import { FieldType, ParticipantMode, decodeUserForms, encodeBlindSubmission, encodeForm, encodeFormSubmission, encodeOtpRequest, encodeOtpVerify } from '../../frontend/src/proto.ts'

const API = process.env.NOON_API ?? 'http://127.0.0.1:39210'
export const OWNER = 'maya@lupyd.com'
const DB = 'noon-test-db'

// ---------------------------------------------------------------- people
// The platform team at Lupyd: the whitelist for the team pulse.
export const TEAM = [
  'jordan.ellis', 'priya.raman', 'sam.okafor', 'lena.fischer', 'diego.alvarez', 'hannah.kim', 'marcus.bell', 'aisha.mensah',
  'tom.becker', 'yuki.tanaka', 'nadia.haddad', 'olivia.grant', 'ravi.shah', 'chloe.martin', 'ben.osei', 'ines.costa',
  'kofi.asante', 'mia.novak', 'arjun.mehta', 'zoe.lambert', 'felix.wagner', 'amara.eze', 'noah.reyes', 'sara.lindqvist',
  'leo.dubois', 'fatima.zahra', 'ethan.cole', 'maya.iyer', 'jonas.berg', 'elena.petrova', 'kai.nakamura', 'grace.liu',
  'omar.farouk', 'ruby.walsh', 'theo.martins', 'anya.volkova', 'luis.moreno', 'isla.campbell', 'daniel.park', 'nora.quinn',
].map((n) => `${n}@lupyd.com`)

// ---------------------------------------------------------------- answers
const rng = (() => {
  let s = 0x9e3779b9
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32)
})()
const pick = <T,>(xs: T[], w?: number[]) => {
  if (!w) return xs[Math.floor(rng() * xs.length)]
  let r = rng() * w.reduce((a, b) => a + b, 0)
  for (let i = 0; i < xs.length; i++) if ((r -= w[i]) < 0) return xs[i]
  return xs[xs.length - 1]
}

// What people actually write when nobody can trace it back.
const BLOCKERS = [
  'Release freezes keep getting extended without anyone saying why.',
  'Too many meetings on Tuesdays and Wednesdays. I lose both days.',
  'On-call rotation is uneven. The same four people carry it.',
  'The migration to the new CI runners has no owner.',
  'I don\'t know how promotions are decided here.',
  'Product changes priorities mid-sprint, every sprint.',
  'Hiring is behind. We are covering two open roles.',
  'Code review turnaround is 3+ days on infra changes.',
  'Honestly fine right now. The offsite helped.',
  'Staging is broken more often than it works.',
  'Feels like decisions are made in DMs, not in the channel.',
  'Burned out after the Q2 launch and never really recovered.',
  'Need clearer ownership between platform and data teams.',
  'Docs for the auth service are two versions out of date.',
  'My manager is great, skip-level less so.',
  '',
  '',
  '',
]

const TEXTS: Record<string, string[]> = {
  positives: ['The team. People actually help each other.', 'Flexible hours.', 'Ownership over what I ship.', 'Good tooling, fast deploys.', 'My manager shields us from chaos.'],
  improvements: ['Fewer status meetings.', 'Clearer promotion criteria.', 'Write decisions down.', 'Stop moving deadlines without context.', 'More headcount on infra.'],
  suggestions: ['Longer breaks between sessions.', 'Less slides, more workshops.', 'Do it again next year!', 'Better vegetarian options.'],
  exit_interview_feedback: ['Growth path was unclear.', 'Great people, slow decisions.', 'Comp fell behind the market.'],
  csat_comments: ['Quick and friendly.', 'Took two follow-ups to resolve.', 'Solved on the first call.', 'Docs could be clearer.'],
  default: ['Nothing to add.', 'All good.', 'More of this, please.', 'Communication could be better.'],
}

type Answer = (field: any) => any
const TEAM_PULSE: Record<string, Answer> = {
  morale: () => pick(['1 - Low', '2 - Mediocre', '3 - Good', '4 - Great', '5 - Excellent'], [2, 5, 12, 14, 6]),
  workload: () => pick(['I have too little to do', 'My workload is manageable', 'I am overwhelmed'], [2, 21, 14]),
  communication: () => pick(['1 - Poor', '2 - Subpar', '3 - Clear & transparent', '4 - Excellent'], [4, 11, 16, 7]),
  blockers: () => pick(BLOCKERS),
}

/** a plausible answer for any template field */
function answer(field: any, overrides: Record<string, Answer> = {}) {
  const v: any = { fieldId: field.id }
  if (overrides[field.name]) {
    const x = overrides[field.name](field)
    return field.type === FieldType.MULTI_SELECT ? { ...v, bitmaskValue: x } : typeof x === 'number' ? { ...v, doubleValue: x } : { ...v, stringValue: x }
  }
  const opts = field.selectOptions?.options ?? []
  switch (field.type) {
    case FieldType.NUMBER: {
      const c = field.numberConfig ?? { min: 0, max: 10 }
      const lo = c.min ?? 0
      const hi = c.max || 10
      return { ...v, doubleValue: Math.round(lo + (hi - lo) * (0.45 + 0.5 * rng() * rng() + 0.1 * rng())) }
    }
    case FieldType.MULTI_SELECT:
      return { ...v, bitmaskValue: 1 << Math.floor(rng() * Math.max(1, opts.length)) }
    case FieldType.CHECKBOX:
      return { ...v, boolValue: field.required || rng() > 0.3 }
    case FieldType.RADIO:
    case FieldType.SELECT:
      return { ...v, stringValue: opts.length ? pick(opts.map((o: any) => o.value), opts.map((_: any, i: number) => 1 + Math.min(i, opts.length - 1 - i) * 2 + (i === opts.length - 2 ? 3 : 0))) : '' }
    default:
      return { ...v, stringValue: field.required || rng() > 0.4 ? pick(TEXTS[field.name] ?? TEXTS.default) : '' }
  }
}

// ---------------------------------------------------------------- API
async function ok(res: Response, what: string) {
  if (!res.ok) throw new Error(`${what}: ${res.status} ${await res.text()}`)
  return res
}
/** EmailOnly token for an address (global if formId = 0), via the emulator's fixed OTP */
export async function token(email: string, formId = 0) {
  await ok(await fetch(`${API}/email/request_otp`, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: encodeOtpRequest({ email, formId }) }), `otp ${email}`)
  const r = await ok(await fetch(`${API}/email/verify_otp`, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: encodeOtpVerify({ email, code: '123456', formId }) }), `verify ${email}`)
  return r.text()
}

function templateForm(name: string, tpl: string, mode: ParticipantMode, allowed: string[], description?: string) {
  const t = TEMPLATES.find((x) => x.name === tpl)
  if (!t) throw new Error(`no template ${tpl}`)
  const now = Math.floor(Date.now() / 1000)
  return {
    id: 0,
    name,
    description: description ?? t.description,
    fields: t.fields.map((f) => ({
      id: f.id, type: f.type, name: f.name, label: f.label, required: f.required, placeholder: f.placeholder, helpText: f.helpText,
      ...(f.numberConfig ? { numberConfig: f.numberConfig } : {}),
      ...(f.options ? { selectOptions: { options: f.options.map((o, i) => ({ label: o, value: o, bit: i })), useBitmask: f.type === FieldType.MULTI_SELECT } } : {}),
    })),
    owner: OWNER, createdAt: now, updatedAt: now, allowedParticipants: allowed, deadline: 0,
    participantMode: mode, participantCap: 0, submissionReplyMessage: '', submissionCount: 0,
  } as any
}

async function createForm(ownerTok: string, form: any): Promise<number> {
  const r = await ok(await fetch(`${API}/forms/create`, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream', Authorization: `EmailOnly ${ownerTok}` }, body: encodeForm(form) }), `create ${form.name}`)
  return (await r.json()).id
}

async function getForm(id: number, auth: string) {
  const { decodeForm } = await import('../../frontend/src/proto.ts')
  const r = await ok(await fetch(`${API}/forms/${id}`, { headers: { Authorization: auth } }), `form ${id}`)
  return decodeForm(new Uint8Array(await r.arrayBuffer()))
}

/** one anonymous response: blind, get signed with `auth`, unblind, submit with no identity */
export async function respond(formId: number, auth: string, values: any[], at = Date.now()) {
  const sub = encodeFormSubmission({ formId, values, submittedAt: at })
  const nonce = crypto.getRandomValues(new Uint8Array(16))
  const combined = new Uint8Array(sub.length + 16)
  combined.set(sub)
  combined.set(nonce, sub.length)
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', combined))
  const pk = await (await ok(await fetch(`${API}/forms/${formId}/public_key`), 'public key')).json()
  const n = mycrypto.bytesToBigIntLE(mycrypto.base64ToBytes(pk.n))
  const e = mycrypto.bytesToBigIntLE(mycrypto.base64ToBytes(pk.e))
  let r = 0n
  do r = mycrypto.randomBigInt(n)
  while (r === 0n || mycrypto.gcd(r, n) !== 1n)
  const blinded = (mycrypto.bytesToBigIntLE(hash) * mycrypto.modPow(r, e, n)) % n
  const sr = await ok(await fetch(`${API}/forms/${formId}/blind_sign`, { method: 'POST', headers: { Authorization: auth, 'Content-Type': 'application/octet-stream' }, body: mycrypto.bigIntToBytesLE(blinded) }), 'blind sign')
  const sBlind = mycrypto.bytesToBigIntLE(new Uint8Array(await sr.arrayBuffer()))
  const sig = (sBlind * mycrypto.modInverse(r, n)) % n
  await ok(await fetch(`${API}/forms/${formId}/submit`, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: encodeBlindSubmission({ signature: mycrypto.bigIntToBytesLE(sig), submission: sub, nonce, payload: hash }) }), 'submit')
}

async function fillForm(id: number, people: string[], overrides: Record<string, Answer> = {}, mode = ParticipantMode.LIST_OF_EMAILS) {
  let done = 0
  for (const email of people) {
    const auth = mode === ParticipantMode.NO_EMAIL_REQUIRED ? `Guest ${crypto.randomUUID()}` : `EmailOnly ${await token(email, id)}`
    const form = await getForm(id, auth)
    // answers trickle in over the past few days
    await respond(id, auth, form.fields.map((f: any) => answer(f, overrides)), Date.now() - Math.floor(rng() * 4 * 86400e3))
    done++
  }
  return done
}

function sql(q: string) {
  const r = spawnSync('docker', ['exec', '-i', DB, 'psql', '-U', 'postgres', '-d', 'noondb', '-v', 'ON_ERROR_STOP=1', '-qc', q], { encoding: 'utf8' })
  if (r.status !== 0) throw new Error(r.stderr)
  return r.stdout
}

async function reset() {
  // local emulator DB only: refuse anything that is not the docker test container
  sql('TRUNCATE form_reply_log, form_submissions, form_allowed_participants, forms, otp_codes, user_subscriptions RESTART IDENTITY CASCADE')
  sql(`INSERT INTO user_subscriptions (owner, tier, subscription_status) VALUES ('email:${OWNER}', 'team', 2)`)
  const own = await token(OWNER)
  const bg: [string, string, ParticipantMode, string[], string?][] = [
    ['Lisbon Offsite Feedback', 'Event Feedback', ParticipantMode.LIST_OF_EMAILS, TEAM.slice(0, 31)],
    ['Manager 360 · Platform', 'Employee Feedback', ParticipantMode.LIST_OF_EMAILS, TEAM.slice(8, 22)],
    ['Customer Satisfaction · Q3', 'Customer Satisfaction', ParticipantMode.NO_EMAIL_REQUIRED, []],
    ['Exit Interview', 'Exit Interview', ParticipantMode.ANY_WITH_EMAIL, []],
  ]
  const fills = [27, 12, 46, 4]
  for (let i = 0; i < bg.length; i++) {
    const [name, tpl, mode, allowed] = bg[i]
    const id = await createForm(own, templateForm(name, tpl, mode, allowed))
    const people = allowed.length ? allowed.slice(0, fills[i]) : Array.from({ length: fills[i] }, (_, k) => `guest${k}.${i}@example.com`)
    const n = await fillForm(id, people, {}, mode)
    console.log(`${name}: form ${id}, ${n} responses`)
  }
}

async function fill(name: string, skip: string[]) {
  const own = await token(OWNER)
  const r = await ok(await fetch(`${API}/forms?page=1&limit=50`, { headers: { Authorization: `EmailOnly ${own}` } }), 'list')
  const forms = decodeUserForms(new Uint8Array(await r.arrayBuffer())).forms.filter((f: any) => f.name === name).sort((a: any, b: any) => Number(b.id) - Number(a.id))
  if (!forms.length) throw new Error(`no form named ${name}`)
  const f = forms[0]
  const people = f.allowedParticipants.filter((e: string) => !skip.includes(e))
  const n = await fillForm(Number(f.id), people.slice(0, Math.round(people.length * 0.9)), TEAM_PULSE)
  console.log(`${name}: form ${f.id}, ${n} more responses`)
}

/** newest form with this name, as the owner sees it */
export async function formId(name: string) {
  const own = await token(OWNER)
  const r = await ok(await fetch(`${API}/forms?page=1&limit=50`, { headers: { Authorization: `EmailOnly ${own}` } }), 'list')
  const ids = decodeUserForms(new Uint8Array(await r.arrayBuffer())).forms.filter((f: any) => f.name === name).map((f: any) => Number(f.id))
  if (!ids.length) throw new Error(`no form named ${name}`)
  return Math.max(...ids)
}

const [cmd, ...args] = process.argv.slice(2)
if (cmd === 'reset') await reset()
else if (cmd === 'fill') await fill(args[0], args.slice(1))
else if (cmd === 'team') console.log(TEAM.join('\n'))
else if (cmd === 'token') console.log(await token(args[0] ?? OWNER))
else if (cmd === 'id') console.log(await formId(args[0]))
else if (cmd === 'drop') sql(`DELETE FROM forms WHERE name = '${args[0].replace(/'/g, "''")}'`)
else if (cmd) throw new Error(`unknown command ${cmd}`)
