import { describe, expect, it, vi, afterEach } from 'vitest'

import { NebulAuthDashboardClient } from './dashboard'

afterEach(() => {
  vi.restoreAllMocks()
})

function getFirstFetchCall(fetchMock: ReturnType<typeof vi.fn>): [string, RequestInit] {
  const firstCall = fetchMock.mock.calls[0]
  expect(firstCall).toBeDefined()

  if (!firstCall || firstCall.length < 2) {
    throw new Error('Expected fetch to be called with url and options')
  }

  const [url, options] = firstCall as [string, RequestInit | undefined]

  if (!options) {
    throw new Error('Expected fetch options to be provided')
  }

  return [url, options]
}

describe('NebulAuthDashboardClient', () => {
  it('adds bearer authorization header', async () => {
    const client = new NebulAuthDashboardClient({
      baseUrl: 'https://api.nebulauth.com/dashboard',
      auth: { mode: 'bearer', bearerToken: 'mk_at_test' },
    })

    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ ok: true }), { status: 200 }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await client.me()

    const [url, options] = getFirstFetchCall(fetchMock)
    expect(url).toBe('https://api.nebulauth.com/dashboard/me')
    const headers = options.headers as Record<string, string>
    expect(headers.Authorization).toBe('Bearer mk_at_test')
  })

  it('adds session cookie header', async () => {
    const client = new NebulAuthDashboardClient({
      baseUrl: 'https://api.nebulauth.com/dashboard',
      auth: { mode: 'session', sessionCookie: 'sess-123' },
    })

    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ ok: true }), { status: 200 }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await client.listUsers()

    const [, options] = getFirstFetchCall(fetchMock)
    const headers = options.headers as Record<string, string>
    expect(headers.Cookie).toBe('mc_session=sess-123')
  })

  it('builds query string for analytics summary days', async () => {
    const client = new NebulAuthDashboardClient({
      baseUrl: 'https://api.nebulauth.com/dashboard',
      auth: { mode: 'bearer', bearerToken: 'mk_at_test' },
    })

    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ totals: {} }), { status: 200 }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await client.analyticsSummary(30)

    const [url] = getFirstFetchCall(fetchMock)
    expect(url).toBe('https://api.nebulauth.com/dashboard/analytics/summary?days=30')
  })

  it('uses keys batch format parameter', async () => {
    const client = new NebulAuthDashboardClient({
      baseUrl: 'https://api.nebulauth.com/dashboard',
      auth: { mode: 'bearer', bearerToken: 'mk_at_test' },
    })

    const fetchMock = vi.fn(async () =>
      new Response('key-1\nkey-2', {
        status: 200,
        headers: { 'content-type': 'text/plain' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await client.bulkCreateKeys({ count: 2, labelPrefix: 'Promo' }, 'txt')

    const [url, options] = getFirstFetchCall(fetchMock)
    expect(url).toBe('https://api.nebulauth.com/dashboard/keys/batch?format=txt')
    expect(options.method).toBe('POST')
  })

  it('throws when session mode is missing cookie', async () => {
    const client = new NebulAuthDashboardClient({
      auth: { mode: 'session' },
    })

    await expect(client.me()).rejects.toThrow(/sessionCookie is required/i)
  })
})
