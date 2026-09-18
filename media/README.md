# media

| File | What |
|---|---|
| `demo.mp4` | 20 s demo, 1920×1080, 30 fps, H.264 + AAC, 1.8 MB. Frame 0 is `demo.jpg`, baked in so every platform picks it as the idle thumbnail. |
| `demo.jpg` | poster frame (t = 9.5 s: the finished graph) |

No narration. Four beats: a defanged IOC typed into the real *New investigation*
field → `Investigate →` → the graph builds itself node by node, with CDN ranges
and parked nameservers arriving already greyed and tagged (defused before the
pivot) → a context-pool lead flips from dashed violet to solid green once a
source corroborates it. It closes on the claim from
[`PURPOSE.md`](../PURPOSE.md): *a 1-hour manual investigation → three minutes*.

Everything on screen is read from this repository: the `:root` tokens in
`frontend/src/styles.css`, `NODE_COLORS` and `NODE_SHAPES` from
`frontend/src/App.jsx`, the textarea placeholder, the `Investigate →` label, and
`frontend/public/logo-512.png`. **No real investigation data appears** — every
label is masked or plainly fictitious (`evil.com`, `185.203.•••.••`).

## How it was made

[`/brag`](https://github.com/latent-spaces/brag) (Claude Code skill) +
[HyperFrames](https://hyperframes.heygen.com/). The composition is HTML + GSAP,
rendered locally through headless Chrome and ffmpeg — no API key, no hosted
render service. 82 s of wall clock for 600 frames on a 2-core VPS.

## Third-party assets baked into `demo.mp4`

- **Music** — *Happy Beats / Business Moves, vol. 12* by [ende.app](https://ende.app/en),
  **CC BY 4.0**. The publisher's [standard license](https://ende.app/en/standard-license)
  permits commercial use and adaptation, and states attribution is appreciated
  but not enforced; it is given here regardless. Verified 2026-09-18.
- **Sound effects** — [Kenney](https://kenney.nl/) (UI clicks, a soft drop, one
  bell) and the [Keyboard Soundpack #1](https://opengameart.org/content/keyboard-soundpack-1-typing-and-single-keystrokes)
  by unicae_games, both **CC0** (public domain).
- **Typefaces** (rendered, not embedded) — Inter and JetBrains Mono, **SIL OFL 1.1**.

These licenses were checked before adding the file because this repository is
source-available and separately licensable for commercial use
([COMMERCIAL.md](../COMMERCIAL.md)): a demo video must not drag an unclear
third-party right into that grant.
