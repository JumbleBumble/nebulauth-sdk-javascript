import { createHash, createHmac } from 'crypto'
import { describe, expect, it, vi, afterEach } from 'vitest'

import { NebulAuthClient } from './index'

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

describe('NebulAuthClient', () => {
  it('defaults baseUrl when omitted', () => {
    const client = new NebulAuthClient({
      bearerToken: 'mk_at_test',
      signingSecret: 'mk_sig_test',
    })

    const canonical = (client as any)._canonicalPath(
      'https://api.nebulauth.com/api/v1/keys/verify',
    )

    expect(canonical).toBe('/keys/verify')
  })

  it('strips base path when building canonical path', () => {
    const client = new NebulAuthClient({
      baseUrl: 'https://api.nebulauth.com/api/v1',
      bearerToken: 'mk_at_test',
      signingSecret: 'mk_sig_test',
    })

    const canonical = (client as any)._canonicalPath(
      'https://api.nebulauth.com/api/v1/keys/verify',
    )

    expect(canonical).toBe('/keys/verify')
  })

  it('builds valid strict signing headers', () => {
    const client = new NebulAuthClient({
      baseUrl: 'https://api.nebulauth.com/api/v1',
      bearerToken: 'mk_at_test',
      signingSecret: 'mk_sig_test',
      replayProtection: 'strict',
    })

    const bodyString = JSON.stringify({ key: 'mk_live_abc' })
    const headers = (client as any)._buildSigningHeaders(
      'POST',
      'https://api.nebulauth.com/api/v1/keys/verify',
      bodyString,
      'mk_sig_test',
    ) as Record<string, string>

    const expectedBodyHash = createHash('sha256')
      .update(bodyString, 'utf8')
      .digest('hex')

    expect(headers['X-Body-Sha256']).toBe(expectedBodyHash)
    expect(headers['X-Timestamp']).toBeTruthy()
    expect(headers['X-Nonce']).toBeTruthy()

    const canonical = `POST\n/keys/verify\n${headers['X-Timestamp']}\n${headers['X-Nonce']}\n${expectedBodyHash}`
    const expectedSignature = createHmac('sha256', 'mk_sig_test')
      .update(canonical)
      .digest('hex')

    expect(headers['X-Signature']).toBe(expectedSignature)
  })

  it('uses nonce mode without X-Body-Sha256 header', () => {
    const client = new NebulAuthClient({
      baseUrl: 'https://api.nebulauth.com/api/v1',
      bearerToken: 'mk_at_test',
      signingSecret: 'mk_sig_test',
      replayProtection: 'nonce',
    })

    const headers = (client as any)._buildAuthHeaders({
      method: 'POST',
      url: 'https://api.nebulauth.com/api/v1/keys/verify',
      bodyString: JSON.stringify({ key: 'mk_live_abc' }),
      usePop: false,
    }) as Record<string, string>

    expect(headers.Authorization).toBe('Bearer mk_at_test')
    expect(headers['X-Body-Sha256']).toBeUndefined()
    expect(headers['X-Signature']).toBeTruthy()
  })

  it('throws if redeemKey is called without service slug', async () => {
    const client = new NebulAuthClient({
      baseUrl: 'https://api.nebulauth.com/api/v1',
      bearerToken: 'mk_at_test',
      signingSecret: 'mk_sig_test',
    })

    await expect(
      client.redeemKey({
        key: 'mk_live_abc',
        discordId: '123',
      }),
    ).rejects.toThrow(/serviceSlug is required/i)
  })

  it('throws if pop auth is requested without popKey', async () => {
    const client = new NebulAuthClient({
      baseUrl: 'https://api.nebulauth.com/api/v1',
      bearerToken: 'mk_at_test',
      signingSecret: 'mk_sig_test',
    })

    await expect(
      client.verifyKey({
        key: 'mk_live_abc',
        usePop: true,
        accessToken: 'v4.public.test',
      }),
    ).rejects.toThrow(/popKey is required/i)
  })

  it('parses JSON responses from post requests', async () => {
    const client = new NebulAuthClient({
      baseUrl: 'https://api.nebulauth.com/api/v1',
      bearerToken: 'mk_at_test',
      signingSecret: 'mk_sig_test',
    })

    const fetchMock = vi.fn(async () => {
      return new Response(JSON.stringify({ redeemed: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    })

    vi.stubGlobal('fetch', fetchMock)

    const result = await client.post('/keys/redeem', {
      key: 'mk_live_abc',
      discordId: '123',
      serviceSlug: 'svc',
    })

    expect(result.statusCode).toBe(200)
    expect(result.ok).toBe(true)
    expect(result.data).toEqual({ redeemed: true })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('verifyKey sends expected endpoint, body, and HWID header', async () => {
    const client = new NebulAuthClient({
      baseUrl: 'https://api.nebulauth.com/api/v1',
      bearerToken: 'mk_at_test',
      signingSecret: 'mk_sig_test',
    })

    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ valid: true }), { status: 200 }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await client.verifyKey({
      key: 'mk_live_abc',
      requestId: 'req-1',
      hwid: 'HWID-1',
    })

    const [url, options] = getFirstFetchCall(fetchMock)
    expect(url).toBe('https://api.nebulauth.com/api/v1/keys/verify')
    expect(options.method).toBe('POST')
    expect(options.body).toBe('{"key":"mk_live_abc","requestId":"req-1"}')

    const headers = options.headers as Record<string, string>
    expect(headers.Authorization).toBe('Bearer mk_at_test')
    expect(headers['X-HWID']).toBe('HWID-1')
    expect(headers['X-Signature']).toBeTruthy()
  })

  it('redeemKey uses default client serviceSlug in payload', async () => {
    const client = new NebulAuthClient({
      baseUrl: 'https://api.nebulauth.com/api/v1',
      bearerToken: 'mk_at_test',
      signingSecret: 'mk_sig_test',
      serviceSlug: 'default-svc',
    })

    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ redeemed: true }), { status: 200 }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await client.redeemKey({
      key: 'mk_live_abc',
      discordId: '123',
      requestId: 'req-2',
    })

    const [url, options] = getFirstFetchCall(fetchMock)
    expect(url).toBe('https://api.nebulauth.com/api/v1/keys/redeem')
    expect(options.body).toBe(
      '{"key":"mk_live_abc","discordId":"123","serviceSlug":"default-svc","requestId":"req-2"}',
    )
  })

  it('supports PoP mode without bearer token on client', async () => {
    const client = new NebulAuthClient({
      baseUrl: 'https://api.nebulauth.com/api/v1',
      replayProtection: 'strict',
    })

    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ valid: true }), { status: 200 }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await client.verifyKey({
      key: 'mk_live_abc',
      usePop: true,
      accessToken: 'v4.public.token',
      popKey: 'pop-key-secret',
    })

    const [, options] = getFirstFetchCall(fetchMock)
    const headers = options.headers as Record<string, string>
    expect(headers.Authorization).toBe('Bearer v4.public.token')
    expect(headers['X-Signature']).toBeTruthy()
  })
})
