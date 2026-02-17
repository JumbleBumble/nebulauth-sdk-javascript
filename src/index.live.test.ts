import { describe, expect, it } from 'vitest'

import { NebulAuthClient } from './index'

const DEFAULT_BASE_URL = 'https://api.nebulauth.com/api/v1'

const enabled = process.env.NEBULAUTH_LIVE_TEST === '1'
const requiredEnv = [
  'NEBULAUTH_BEARER_TOKEN',
  'NEBULAUTH_SIGNING_SECRET',
  'NEBULAUTH_TEST_KEY',
] as const

const missing = requiredEnv.filter((name) => !process.env[name])
const runLive = enabled && missing.length === 0
const testIfLive = runLive ? it : it.skip

describe('NebulAuth live integration (env-gated)', () => {
  it('validates env when live mode is enabled', () => {
    if (enabled) {
      expect(missing).toEqual([])
    }
  })

  testIfLive('calls /keys/verify against live API', async () => {
    const client = new NebulAuthClient({
      baseUrl: process.env.NEBULAUTH_BASE_URL ?? DEFAULT_BASE_URL,
      bearerToken: process.env.NEBULAUTH_BEARER_TOKEN!,
      signingSecret: process.env.NEBULAUTH_SIGNING_SECRET!,
      replayProtection: 'strict',
    })

    const response = await client.verifyKey({
      key: process.env.NEBULAUTH_TEST_KEY!,
      requestId: `live-js-${Date.now()}`,
      hwid: process.env.NEBULAUTH_TEST_HWID,
    })

    expect(typeof response.statusCode).toBe('number')
    expect(typeof response.data).toBe('object')
    expect(response.data).toHaveProperty('valid')
  })

  testIfLive('calls /auth/verify bootstrap endpoint against live API', async () => {
    const client = new NebulAuthClient({
      baseUrl: process.env.NEBULAUTH_BASE_URL ?? DEFAULT_BASE_URL,
      bearerToken: process.env.NEBULAUTH_BEARER_TOKEN!,
      signingSecret: process.env.NEBULAUTH_SIGNING_SECRET!,
      replayProtection: 'strict',
    })

    const response = await client.authVerify({
      key: process.env.NEBULAUTH_TEST_KEY!,
      hwid: process.env.NEBULAUTH_TEST_HWID,
      requestId: `live-js-bootstrap-${Date.now()}`,
    })

    expect(typeof response.statusCode).toBe('number')
    expect(typeof response.data).toBe('object')
    expect(response.data).toHaveProperty('valid')
  })
})
