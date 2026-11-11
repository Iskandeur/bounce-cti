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

## Accessibility baseline

`a11y.spec.js` runs axe-core on the main screen (dark and light theme) and on
the login screen. The rules the app violates today are listed in
`a11y-baseline.js`, each with the reason it is tolerated for now. A violated
rule missing from that list fails the suite. The check is per rule: one more
element breaking a listed rule passes, and a listed rule that stopped firing is
not reported. To fix a rule, fix the app and delete its line. An axe-core
update can add rules, and with them new failures.

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
- On a phone (375x812): the drawers, sideways scrolling, the toolbar's two rows
  and the 11px floor on text sizes. Nothing else of the phone layout.
