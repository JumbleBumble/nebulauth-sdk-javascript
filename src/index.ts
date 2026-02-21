import { createHash, createHmac, randomBytes } from 'crypto'

const DEFAULT_BASE_URL = 'https://api.nebulauth.com/api/v1'

/**
 * Replay protection mode used for bearer-auth requests.
 * - `none`: bearer token only
 * - `nonce`: signature without `X-Body-Sha256` header
 * - `strict`: full signature with `X-Body-Sha256`
 */
export type ReplayProtectionMode = 'none' | 'nonce' | 'strict'

/**
 * Normalized SDK response returned by all client calls.
 */
export interface NebulAuthResponse<T = unknown> {
  statusCode: number
  ok: boolean
  data: T
  headers: Record<string, string>
}

/**
 * Client constructor options.
 */
export interface NebulAuthClientOptions {
  baseUrl?: string
  bearerToken?: string
  signingSecret?: string
  serviceSlug?: string
  replayProtection?: ReplayProtectionMode
  timeoutMs?: number
}

/**
 * Optional Proof-of-Possession (PoP) auth inputs for per-request override.
 */
export interface PopAuthOptions {
  usePop?: boolean
  accessToken?: string
  popKey?: string
}

/**
 * Input payload for `verifyKey`.
 */
export interface VerifyKeyInput extends PopAuthOptions {
  key: string
  requestId?: string
  hwid?: string
}

/**
 * Input payload for `authVerify`.
 */
export interface AuthVerifyInput {
  key: string
  hwid?: string
  requestId?: string
}

/**
 * Input payload for `redeemKey`.
 */
export interface RedeemKeyInput extends PopAuthOptions {
  key: string
  discordId: string
  serviceSlug?: string
  requestId?: string
}

/**
 * Input payload for `resetHwid`.
 */
export interface ResetHwidInput extends PopAuthOptions {
  discordId?: string
  key?: string
  requestId?: string
}


export interface GenericPostOptions extends PopAuthOptions {
  extraHeaders?: Record<string, string>
}

interface VerifyKeyBody {
  key: string
  requestId?: string
}

interface AuthVerifyBody {
  key: string
  hwid?: string
  requestId?: string
}

interface RedeemBody {
  key: string
  discordId: string
  serviceSlug: string
  requestId?: string
}

interface ResetHwidBody {
  discordId?: string
  key?: string
  requestId?: string
}

export class NebulAuthClient {
  private readonly baseUrl: string
  private readonly basePath: string
  private readonly bearerToken?: string
  private readonly signingSecret?: string
  private readonly serviceSlug?: string
  private readonly replayProtection: ReplayProtectionMode
  private readonly timeoutMs: number

  constructor(options: NebulAuthClientOptions = {}) {
    const resolvedBaseUrl = options.baseUrl?.trim() || DEFAULT_BASE_URL

    this.baseUrl = resolvedBaseUrl.replace(/\/$/, '')
    this.basePath = new URL(this.baseUrl).pathname.replace(/\/$/, '')
    this.bearerToken = options.bearerToken
    this.signingSecret = options.signingSecret
    this.serviceSlug = options.serviceSlug
    this.replayProtection = options.replayProtection ?? 'strict'
    this.timeoutMs = options.timeoutMs ?? 15_000

    if (!['none', 'nonce', 'strict'].includes(this.replayProtection)) {
      throw new Error('replayProtection must be one of: none, nonce, strict')
    }
  }

  async verifyKey(input: VerifyKeyInput): Promise<NebulAuthResponse> {
    const payload: VerifyKeyBody = { key: input.key }
    if (input.requestId) payload.requestId = input.requestId

    const extraHeaders: Record<string, string> = {}
    if (input.hwid) {
      extraHeaders['X-HWID'] = input.hwid
    }

    return this._post('/keys/verify', payload, {
      usePop: Boolean(input.usePop),
      accessToken: input.accessToken,
      popKey: input.popKey,
      extraHeaders,
    })
  }

  async authVerify(input: AuthVerifyInput): Promise<NebulAuthResponse> {
    const payload: AuthVerifyBody = { key: input.key }
    if (input.hwid) payload.hwid = input.hwid
    if (input.requestId) payload.requestId = input.requestId

    return this._post('/auth/verify', payload)
  }


  async redeemKey(input: RedeemKeyInput): Promise<NebulAuthResponse> {
    const slug = input.serviceSlug || this.serviceSlug
    if (!slug) {
      throw new Error('serviceSlug is required either in constructor or redeemKey call')
    }

    const payload: RedeemBody = {
      key: input.key,
      discordId: input.discordId,
      serviceSlug: slug,
    }
    if (input.requestId) payload.requestId = input.requestId

    return this._post('/keys/redeem', payload, {
      usePop: Boolean(input.usePop),
      accessToken: input.accessToken,
      popKey: input.popKey,
    })
  }

  /**
   * Requires at least one of `discordId` or `key`.
   */
  async resetHwid(input: ResetHwidInput): Promise<NebulAuthResponse> {
    if (!input.discordId && !input.key) {
      throw new Error('resetHwid requires at least discordId or key')
    }

    const payload: ResetHwidBody = {}
    if (input.discordId) payload.discordId = input.discordId
    if (input.key) payload.key = input.key
    if (input.requestId) payload.requestId = input.requestId

    return this._post('/keys/reset-hwid', payload, {
      usePop: Boolean(input.usePop),
      accessToken: input.accessToken,
      popKey: input.popKey,
    })
  }


  async post(
    endpoint: string,
    payload: object,
    options: GenericPostOptions = {},
  ): Promise<NebulAuthResponse> {
    return this._post(endpoint, payload, options)
  }

  private async _post(
    endpoint: string,
    payload: object,
    options: GenericPostOptions = {},
  ): Promise<NebulAuthResponse> {
    const url = this._endpointUrl(endpoint)
    const bodyString = JSON.stringify(payload)

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...this._buildAuthHeaders({
        method: 'POST',
        url,
        bodyString,
        usePop: Boolean(options.usePop),
        accessToken: options.accessToken,
        popKey: options.popKey,
      }),
      ...(options.extraHeaders ?? {}),
    }

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this.timeoutMs)

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: bodyString,
        signal: controller.signal,
      })

      const text = await response.text()
      let data: unknown
      try {
        data = text ? JSON.parse(text) : {}
      } catch {
        data = { error: text }
      }

      return {
        statusCode: response.status,
        ok: response.ok,
        data,
        headers: Object.fromEntries(response.headers),
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown request error'
      throw new Error(`NebulAuth request failed: ${message}`)
    } finally {
      clearTimeout(timer)
    }
  }

  private _buildAuthHeaders(input: {
    method: string
    url: string
    bodyString: string
    usePop: boolean
    accessToken?: string
    popKey?: string
  }): Record<string, string> {
    if (input.usePop) {
      if (!input.accessToken) {
        throw new Error('accessToken is required when usePop=true')
      }
      if (!input.popKey) {
        throw new Error('popKey is required when usePop=true')
      }

      return {
        Authorization: `Bearer ${input.accessToken}`,
        ...this._buildSigningHeaders(input.method, input.url, input.bodyString, input.popKey),
      }
    }

    if (!this.bearerToken) {
      throw new Error('bearerToken is required for bearer auth mode')
    }

    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.bearerToken}`,
    }

    if (this.replayProtection !== 'none') {
      if (!this.signingSecret) {
        throw new Error('signingSecret is required when replayProtection is nonce/strict')
      }

      const signingHeaders = this._buildSigningHeaders(
        input.method,
        input.url,
        input.bodyString,
        this.signingSecret,
      )

      if (this.replayProtection === 'nonce') {
        delete signingHeaders['X-Body-Sha256']
      }

      Object.assign(headers, signingHeaders)
    }

    return headers
  }

  private _buildSigningHeaders(
    method: string,
    url: string,
    bodyString: string,
    secret: string,
  ): Record<string, string> {
    const path = this._canonicalPath(url)
    const timestamp = Date.now().toString()
    const nonce = randomBytes(16).toString('base64url')
    const bodyHash = createHash('sha256').update(bodyString, 'utf8').digest('hex')

    const canonical = `${method.toUpperCase()}\n${path}\n${timestamp}\n${nonce}\n${bodyHash}`
    const signature = createHmac('sha256', secret).update(canonical).digest('hex')

    return {
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
      'X-Signature': signature,
      'X-Body-Sha256': bodyHash,
    }
  }

  private _canonicalPath(url: string): string {
    const target = new URL(url)
    let path = target.pathname || '/'

    if (this.basePath && path.startsWith(this.basePath)) {
      path = path.slice(this.basePath.length) || '/'
    }

    return path.startsWith('/') ? path : `/${path}`
  }

  private _endpointUrl(endpoint: string): string {
    const base = `${this.baseUrl}/`
    return new URL(endpoint.replace(/^\//, ''), base).toString()
  }
}

export * from './dashboard'
