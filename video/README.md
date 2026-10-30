# Noon showcase video

Deterministic pipeline that renders the Noon product showcase (≈64 s, 1920×1080)
from code: the animated logo, live recordings of the real Noon app, a voiceover,
an original score and synthesised SFX. Ported from the Lupyd showcase pipeline.
Creative direction: [DIRECTION.md](DIRECTION.md).

```
video/
├── logo/                 the logo, traced from assets/noon.webp and animated
│   ├── trace.py          noon.webp → layered noon-logo.svg (pnpm logo:trace)
│   ├── engine.js         WebGL logo: flames, spinning spirals, stars (shared with the stage)
│   └── index.html        standalone preview of the intro (pnpm logo:render)
├── scripts/seed.ts       demo data through the real API + blind-signature flow (bun)
├── scripts/app.mjs       the real frontend, built and served as https://noon.lupyd.com
├── scripts/beats.mjs     what each recorded beat does in the app
├── scripts/record.mjs    screen-records beats → beats/<id>.mp4 + .json
├── scripts/timeline.mjs  shot list + VO durations → out/timeline.json
├── stage/                the 1920×1080 stage (scenes in stage/src/scenes/noon.ts)
├── vo/script.json        VO lines (Kokoro-82M: pnpm vo)
├── music/compose.py      original score; music/sfx.py synthesised SFX
└── scripts/render.mjs, mix.mjs   parallel render, final mix
```

## Run

Needs the local emulator stack: Postgres (`docker compose up -d db` in `..`) and the
server with `EMULATOR_MODE=true SKIP_EMAIL_SENDING=true` and
`DB_CONN_STR=postgres://postgres:password123@127.0.0.1:39222/noondb?sslmode=disable`.

```sh
pnpm install
bun scripts/seed.ts reset                       # owner, background forms, responses
node scripts/record.mjs create respond results  # in this order
pnpm vo                                         # once, or when vo/script.json changes
pnpm draft                                      # → out/noon-showcase-draft.mp4 (~1 min)
node scripts/render.mjs && node scripts/mix.mjs --video out/video-default.mp4 --out out/noon-showcase-1080p.mp4
```
