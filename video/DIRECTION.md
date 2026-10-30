# Noon showcase: direction

Same craft rules as the Lupyd showcase (Linear / Raycast / Apple launch films): one
thing on screen at a time, big and crisp, deliberate motion, no clutter. The pipeline is
the Lupyd one, ported: record the real app, stage it, VO + score + SFX, render.

## The story in one line

People only tell the truth when it can't be traced back to them. Noon makes that a
property of the math, not a promise in a privacy policy.

## Audience

Team leads, HR and people-ops, founders running pulse checks, educators collecting course
feedback. They have all used "anonymous" forms and know nobody quite believes them.
Lead with honest feedback at work; the cryptography is the proof, not the pitch.

## Principles

1. **Real app, real content.** Every UI frame is the real Noon frontend talking to the
   real Rust server (local emulator stack: `EMULATOR_MODE=true`, OTP 123456). Forms,
   whitelists and every response are created through the real API, and responses go
   through the real blind-signature protocol (`scripts/seed.ts`). Nothing is mocked.
2. **Record, then edit.** Each beat is a live screen recording driven by puppeteer
   (`scripts/beats.mjs` → `scripts/record.mjs`), 1536×864 @2×, actions and rects logged.
   The stage only adds framing, camera, type and transitions.
3. **Camera moves are derived** from logged rects; at most one push-in per beat.
4. **Dark app theme everywhere.** The background is the logo's night navy, so the film
   opens and closes inside the logo's world.
5. **No slop.** No floating chips, eyebrow labels, neon outlines, glow blobs or gradient
   text. Information is carried by the real UI plus the VO; a plain title card at most.
6. **Live only.** The blind-signature beat animates the respondent's *actual* answer from
   the respond recording, not a stock diagram.
7. **Rhythm.** Beats 4–9 s, cuts on the music (120 BPM grid), whole film 60–75 s.

## Shot list (VO in quotes)

| # | Beat | What happens | Camera |
|---|------|--------------|--------|
| 1 | Intro | Open inside one sun's spiral, spirals turning; pull out to the whole logo as the flames ignite; logo slides left, "Introducing Noon" sets on the right. "People only tell you the truth when it's safe to. Introducing Noon." | logo camera |
| 2 | Problem | Type card: *"Anonymous" forms still know who you are.* "Most anonymous forms still know who answered. They just promise not to look." | static |
| 3 | Create | Templates → Team Pulse Check → builder prefilled; rename to *Q3 Team Pulse*; whitelist mode; paste the team's 40 emails; Create Form → share link. Title "Create." "Start from a template, choose exactly who can respond, and share one link." | push-in on the whitelist |
| 4 | Respond | One phone, the real form at 390×844: email → one-time code → three taps and a sentence → submit. Title "Respond." "Your team proves they're invited with a one-time code. Then they answer." | static phone |
| 5 | Blind | The respondent's real answer locks into noise (blinded), the Noon server signs it without reading it, it unlocks and lands with no name; the email goes to a separate list. "Before anything leaves the browser, Noon blinds it. The server signs what it can't read. So the answer arrives with proof, but no name." | staged, live data |
| 6 | Results | Owner's results for Q3 Team Pulse (real responses): table → Analytics & Charts → the Verified Respondents panel. Title "Results." "You see who responded, and what they said. Never who said what." | one push on the decoupling note |
| 7 | CTA | Back to the logo; it settles left, "Noon", *Honest answers, by design.* and noon.lupyd.com. "Noon. Free to start, and open source." | logo camera |

## Data

- Owner: maya@halcyonlabs.io (Team plan), Halcyon Labs platform org.
- Background forms on the dashboard: Lisbon Offsite Feedback (27), Manager 360 · Platform
  (12), Customer Satisfaction · Q3 (46, open guest mode), Exit Interview (4).
- Q3 Team Pulse is created live in the create beat; its responses come from the respond
  beat plus `seed.ts fill` before the results beat records.

## Acceptance

- Intro frames match the traced logo; no seams while the spirals turn.
- Every click ripple lands on its element; push-ins frame meaningful UI.
- The phone is fully inside the frame (≥ 36 px clear top and bottom).
- Draft render in minutes; previews before finals.
