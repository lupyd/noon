# Noon showcase: direction

The pipeline is ported from the Lupyd showcase (record the real app, stage it, VO + score
+ SFX, render), but the film is Noon's own: its own concept, look and music. Nothing
visual or musical is carried over from Lupyd.

## The story in one line

People only tell the truth when it can't be traced back to them. Noon makes that a
property of the math, not a promise in a privacy policy.

## Concept: night to noon

The film opens in the logo's night sky (the logo is two suns burning in the dark): the
spiral pull-out, "Introducing Noon", and the problem ("anonymous" forms still know who
you are) all happen at night. On the cut into the product the sun rises: a warm band
sweeps up from below the frame and everything after it is daylight. The product, where
answers come out into the open with nothing hiding in the shadows, plays at noon. The end
card puts the burning logo on daylight.

- **Palette** from the logo: night navy #232156 (ink by day), sun #e75b32, amber #ef8d2c,
  cream #f8e4a6; daylight is warm paper (#fffaf0 → #f2deb4).
- **Type**: Fraunces (soft, warm serif) for everything the film says; Inter only inside UI
  details.
- **App**: Noon's own light theme, framed as a light browser window on noon.lupyd.com
  (Noon is a web app); the respondent on one phone.
- **Music**: an original score that follows the light (`music/compose.py`, 96 BPM): choir,
  celesta and cello at night in D minor; at sunrise a strum lands on the cut and it opens
  to F major with fingerpicked nylon guitar, marimba, acoustic bass and hand percussion;
  pizzicato and celesta hush the blind-signature beat; a flute hook carries the results
  and the end card.

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
4. **Night, then noon.** Night navy only before the sunrise; daylight paper after it.
5. **No slop.** No floating chips, eyebrow labels, neon outlines, glow blobs or gradient
   text. Information is carried by the real UI plus the VO; a plain title card at most.
6. **Live only.** The blind-signature beat animates the respondent's *actual* answer from
   the respond recording, not a stock diagram.
7. **Rhythm.** Cuts on the music (96 BPM grid), whole film 60–75 s.

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

- People are on lupyd.com (the owner, maya@lupyd.com on a Team plan, and the 40-person
  platform team); open-form guests use reserved example domains. No real third-party
  companies or domains anywhere.
- Background forms on the dashboard: Lisbon Offsite Feedback (27), Manager 360 · Platform
  (12), Customer Satisfaction · Q3 (46, open guest mode), Exit Interview (4).
- Q3 Team Pulse is created live in the create beat; its responses come from the respond
  beat plus `seed.ts fill` before the results beat records.

## Acceptance

- Intro frames match the traced logo; no seams while the spirals turn.
- Every click ripple lands on its element; push-ins frame meaningful UI.
- The phone is fully inside the frame (≥ 36 px clear top and bottom).
- Draft render in minutes; previews before finals.
