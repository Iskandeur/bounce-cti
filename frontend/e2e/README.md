# Browser suite

Playwright tests of the app in Chromium, with no backend. They run in CI
(`.github/workflows/ci.yml`, job "Frontend end-to-end") and locally:

```bash
cd frontend
npm ci
npx playwright install chromium     # once per Playwright version
npm run test:e2e                    # the whole suite, about 5 s
npx playwright test graph           # one file
npx playwright test --repeat-each 3 # look for a flaky test
npx playwright test --ui            # watch it run
```

## What is mocked

- **The server.** Playwright starts the Vite dev server on `127.0.0.1:5199`
  (`playwright.config.js`). The port is its own and `--strictPort` is set: if
  something already listens there the run stops, so the suite never tests another
  checkout's server.
- **`/api/`.** `mockApi.js` answers every request in the browser from
  `fixtures/data.js`. The Vite proxy to the backend is never reached.
- **`/ws/<inv_id>`.** A mocked WebSocket sends `{kind: 'snapshot', graph}` on
  connect, as the backend does. `api.push(inv, event)` sends one more event
  (`node_added`, `status_change`…).

Two guards run in every test (`harness.js`):

- An `/api/` call the mock has no answer for gets a 501 and **fails the test**,
  with the method and path. A new endpoint in the app therefore needs a fixture
  before the suite is green again. Only reads are mocked: a test that makes the
  app write (start, rerun, delete, note) adds its own `page.route`.
- An uncaught error in the page (`pageerror`) fails the test.

## Fixtures

`fixtures/data.js` is written by hand, small and synthetic: `example.com`,
`192.0.2.0/24`, `198.51.100.0/24`, `AS64496`, made-up ids and hashes. The
repository is public. Never paste a real investigation, a real name or a key
into it. The shapes follow `backend/main.py`; when a route's answer changes,
change the fixture with it.

## Accessibility

`a11y.spec.js` runs axe-core, in the dark and the light theme, on the main
screen (Report tab of the fixture investigation) and on each other tab of the
right panel (Node on a tagged node, Timeline, Actions, Chat), and on the login
screen. It fails on any violated rule. `a11y-baseline.js` is the list of
tolerated rules; it is empty. A rule goes there only when its fix cannot be in
the same change, with the reason. An axe-core update can add rules, and with
them new failures.

`buttons.spec.js` measures the rules of the buttons on the same screens (and at
375px): an accessible name, at least 24x24px to press, no glyph in a label, a
toggle that keeps its label and flips `aria-pressed`, a 2px focus ring, a
disabled button that is dimmed and has no hover, and the contrast of each
control when hovered, in both themes (4.5:1 for text, 3:1 for an icon alone).
The sources are checked against the same rules by `src/lib/icons.test.js`.

`button-style.spec.js` measures the look (the "Buttons" block of
`src/styles.css`): one filled button in each panel and each dialog (the share
dialog and the admin panel included, with routes of its own for what they
fetch), no button that moves or changes size when hovered or pressed, 4.5:1 for
every kind of button at rest, hovered and pressed in both themes, the check
mark of "copied" that draws itself, and a busy button that changes its label,
keeps its width and runs a line under it. The last two are also run under
`prefers-reduced-motion`. `src/lib/buttons.test.js` checks the stylesheet.

axe checks what is on the page when it runs, and leaves out what it cannot
measure (text over a translucent background, such as the graph toolbar). A
running or failed investigation, the admin panel, the modals and the shared
view are not opened by this test.

## What the suite does not cover

- Clicks on the graph canvas. Cytoscape draws in a `<canvas>` and places the
  nodes with a randomised layout, so a node has no stable position to click.
  Nodes are selected through the search field and the report's IOC chips.
- Pixel comparisons. There is no `toHaveScreenshot` baseline: rendering differs
  per OS and the graph layout is randomised.
- The backend, and whether the fixtures still match it.
- Starting, rerunning or deleting an investigation, uploads, the chat, the
  Actions tab, the admin panel, the share modal, the shared view, the demo build.
- Firefox and WebKit.
- On a phone (375x812): the drawers, sideways scrolling, the toolbar's two rows,
  the 11px floor on text sizes, and the heights of the history and of the agent
  log in the sidebar drawer. Nothing else of the phone layout.
