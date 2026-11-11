// The backend, replaced in the browser: every /api/ request is answered here
// from e2e/fixtures/data.js, and /ws/<inv_id> by a mocked WebSocket that sends
// the graph snapshot, as the real one does on connect.
import {
  ME, VERTICALS, QUOTA, INVESTIGATIONS, GRAPHS, TRANSCRIPTS, LEADS,
  crossInvestigations, evidence,
} from './fixtures/data.js'

const json = (body, status = 200) => ({ status, json: body })
const notFound = json({ detail: 'not found' }, 404)

// [method, path, answer]. Only reads: a test that makes the app write
// (start, rerun, delete, note…) has to add its own page.route for it.
const ROUTES = [
  ['GET', /^\/api\/verticals$/, () => json(VERTICALS)],
  ['GET', /^\/api\/quota$/, () => json(QUOTA)],
  ['GET', /^\/api\/investigations$/, () => json(INVESTIGATIONS)],
  ['GET', /^\/api\/investigations\/([^/]+)\/transcript$/, ([, inv]) =>
    TRANSCRIPTS[inv] ? json(TRANSCRIPTS[inv]) : notFound],
  ['GET', /^\/api\/investigations\/([^/]+)\/leads$/, ([, inv]) =>
    GRAPHS[inv] ? json(LEADS) : notFound],
  ['GET', /^\/api\/investigations\/([^/]+)\/nodes\/([^/]+)\/cross_investigations$/, ([, inv, node]) => {
    const body = crossInvestigations(inv, node)
    return body ? json(body) : notFound
  }],
  ['GET', /^\/api\/investigations\/([^/]+)\/nodes\/([^/]+)\/evidence$/, ([, inv, node]) => {
    const body = evidence(inv, node)
    return body ? json(body) : notFound
  }],
]

export async function mockApi(page, { authenticated = true } = {}) {
  // Calls no route above answers. The harness fails the test when this list is
  // not empty, so an endpoint the app starts calling cannot go unnoticed.
  const unhandled = []
  const sockets = new Map()

  await page.route(url => url.pathname.startsWith('/api/'), async (route) => {
    const request = route.request()
    const { pathname } = new URL(request.url())
    if (request.method() === 'GET' && pathname === '/api/auth/me') {
      return route.fulfill(authenticated ? json(ME) : json({ detail: 'not authenticated' }, 401))
    }
    for (const [method, path, answer] of ROUTES) {
      const match = request.method() === method && pathname.match(path)
      if (match) return route.fulfill(answer(match))
    }
    unhandled.push(`${request.method()} ${pathname}`)
    return route.fulfill(json({ detail: 'e2e: no mock for this call' }, 501))
  })

  await page.routeWebSocket(/^wss?:\/\/[^/]+\/ws\/[^/?]+$/, (ws) => {
    const inv = new URL(ws.url()).pathname.split('/').pop()
    // The backend closes with 4403 on an investigation the user does not own.
    if (!GRAPHS[inv]) return ws.close({ code: 4403 })
    sockets.set(inv, ws)
    ws.send(JSON.stringify({ kind: 'snapshot', graph: GRAPHS[inv] }))
  })

  return {
    unhandled,
    // Send one more event on the open socket of an investigation, as the
    // backend does while an agent runs ({kind: 'node_added', node}, …).
    push(inv, event) {
      const ws = sockets.get(inv)
      if (!ws) throw new Error(`no open WebSocket for investigation ${inv}`)
      ws.send(JSON.stringify(event))
    },
  }
}
