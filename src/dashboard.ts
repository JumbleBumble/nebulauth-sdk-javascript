const DEFAULT_DASHBOARD_BASE_URL = 'https://api.nebulauth.com/dashboard'

export interface DashboardResponse<T = unknown> {
  statusCode: number
  ok: boolean
  data: T
  headers: Record<string, string>
}

export type DashboardHttpMethod = 'GET' | 'POST' | 'PATCH' | 'DELETE'

export type DashboardAuthMode = 'session' | 'bearer'

export interface DashboardAuthOptions {
  mode: DashboardAuthMode
  sessionCookie?: string
  bearerToken?: string
}

export interface DashboardClientOptions {
  baseUrl?: string
  auth?: DashboardAuthOptions
  timeoutMs?: number
}

export interface DashboardRequestOptions {
  auth?: DashboardAuthOptions
  query?: Record<string, string | number | boolean | null | undefined>
  headers?: Record<string, string>
}

export interface LoginRequest {
  email: string
  password: string
}

export interface CustomerUpdateRequest {
  requireDiscordRedeem?: boolean
  requireHwid?: boolean
  paused?: boolean
}

export interface TeamMemberCreateRequest {
  email: string
  password: string
  role: 'READONLY' | 'MEMBER' | 'ADMIN'
}

export interface TeamMemberUpdateRequest {
  role?: 'READONLY' | 'MEMBER' | 'ADMIN'
  password?: string
}

export interface KeyCreateRequest {
  label?: string
  durationHours?: number
  metadata?: Record<string, unknown>
}

export interface KeyBatchCreateRequest {
  labelPrefix?: string
  count: number
  durationHours?: number
  keyOnly?: boolean
  metadata?: Record<string, unknown>
}

export interface KeyUpdateRequest {
  label?: string
  durationHours?: number
  metadata?: Record<string, unknown>
}

export interface KeyRevokeRequest {
  reason?: string
}

export interface RevokeSessionRequest {
  reason?: string
  revokeKey?: boolean
  resetHwid?: boolean
  blacklistDiscord?: boolean
  terminateAllForKey?: boolean
  terminateAllForToken?: boolean
}

export interface RevokeAllSessionsRequest {
  reason?: string
  keyId?: string
  tokenId?: string
}

export interface CheckpointStepInput {
  adUrl: string
}

export interface CheckpointCreateRequest {
  name: string
  durationHours: number
  isActive: boolean
  referrerDomainOnly?: boolean
  steps: CheckpointStepInput[]
}

export interface CheckpointUpdateRequest {
  name?: string
  durationHours?: number
  isActive?: boolean
  referrerDomainOnly?: boolean
  steps?: CheckpointStepInput[]
}

export interface BlacklistCreateRequest {
  type: 'DISCORD' | 'IP'
  value: string
  reason?: string
}

export interface ApiTokenCreateRequest {
  scopes: string[]
  replayProtection: 'none' | 'nonce' | 'strict'
  authMode: 'bearer' | 'pop_optional' | 'pop_required'
  expiresAt?: string | null
}

export interface ApiTokenUpdateRequest {
  scopes?: string[]
  replayProtection?: 'none' | 'nonce' | 'strict'
  authMode?: 'bearer' | 'pop_optional' | 'pop_required'
  expiresAt?: string | null
}

export class NebulAuthDashboardClient {
  private readonly baseUrl: string
  private readonly defaultAuth?: DashboardAuthOptions
  private readonly timeoutMs: number

  constructor(options: DashboardClientOptions = {}) {
    this.baseUrl = (options.baseUrl?.trim() || DEFAULT_DASHBOARD_BASE_URL).replace(/\/$/, '')
    this.defaultAuth = options.auth
    this.timeoutMs = options.timeoutMs ?? 15_000
  }

  async login(payload: LoginRequest, options: DashboardRequestOptions = {}) {
    return this.request('POST', '/auth/login', payload, options)
  }

  async logout(options: DashboardRequestOptions = {}) {
    return this.request('POST', '/auth/logout', {}, options)
  }

  async me(options: DashboardRequestOptions = {}) {
    return this.request('GET', '/me', undefined, options)
  }

  async getCustomer(options: DashboardRequestOptions = {}) {
    return this.request('GET', '/customer', undefined, options)
  }

  async updateCustomer(payload: CustomerUpdateRequest, options: DashboardRequestOptions = {}) {
    return this.request('PATCH', '/customer', payload, options)
  }

  async createUser(payload: TeamMemberCreateRequest, options: DashboardRequestOptions = {}) {
    return this.request('POST', '/users', payload, options)
  }

  async listUsers(options: DashboardRequestOptions = {}) {
    return this.request('GET', '/users', undefined, options)
  }

  async updateUser(id: string, payload: TeamMemberUpdateRequest, options: DashboardRequestOptions = {}) {
    return this.request('PATCH', `/users/${encodeURIComponent(id)}`, payload, options)
  }

  async deleteUser(id: string, options: DashboardRequestOptions = {}) {
    return this.request('DELETE', `/users/${encodeURIComponent(id)}`, undefined, options)
  }

  async createKey(payload: KeyCreateRequest, options: DashboardRequestOptions = {}) {
    return this.request('POST', '/keys', payload, options)
  }

  async bulkCreateKeys(payload: KeyBatchCreateRequest, format: 'json' | 'csv' | 'txt' = 'json', options: DashboardRequestOptions = {}) {
    return this.request('POST', '/keys/batch', payload, {
      ...options,
      query: { ...(options.query ?? {}), format },
    })
  }

  async extendKeyDurations(hours: number, options: DashboardRequestOptions = {}) {
    return this.request('POST', '/keys/extend-duration', { hours }, options)
  }

  async getKey(id: string, options: DashboardRequestOptions = {}) {
    return this.request('GET', `/keys/${encodeURIComponent(id)}`, undefined, options)
  }

  async listKeys(options: DashboardRequestOptions = {}) {
    return this.request('GET', '/keys', undefined, options)
  }

  async updateKey(id: string, payload: KeyUpdateRequest, options: DashboardRequestOptions = {}) {
    return this.request('PATCH', `/keys/${encodeURIComponent(id)}`, payload, options)
  }

  async resetKeyHwid(id: string, options: DashboardRequestOptions = {}) {
    return this.request('POST', `/keys/${encodeURIComponent(id)}/reset-hwid`, {}, options)
  }

  async deleteKey(id: string, payload: KeyRevokeRequest = {}, options: DashboardRequestOptions = {}) {
    return this.request('DELETE', `/keys/${encodeURIComponent(id)}`, payload, options)
  }

  async listKeySessions(options: DashboardRequestOptions = {}) {
    return this.request('GET', '/key-sessions', undefined, options)
  }

  async revokeKeySession(id: string, payload: RevokeSessionRequest, options: DashboardRequestOptions = {}) {
    return this.request('DELETE', `/key-sessions/${encodeURIComponent(id)}`, payload, options)
  }

  async revokeAllKeySessions(payload: RevokeAllSessionsRequest, options: DashboardRequestOptions = {}) {
    return this.request('POST', '/key-sessions/revoke-all', payload, options)
  }

  async listCheckpoints(options: DashboardRequestOptions = {}) {
    return this.request('GET', '/checkpoints', undefined, options)
  }

  async getCheckpoint(id: string, options: DashboardRequestOptions = {}) {
    return this.request('GET', `/checkpoints/${encodeURIComponent(id)}`, undefined, options)
  }

  async createCheckpoint(payload: CheckpointCreateRequest, options: DashboardRequestOptions = {}) {
    return this.request('POST', '/checkpoints', payload, options)
  }

  async updateCheckpoint(id: string, payload: CheckpointUpdateRequest, options: DashboardRequestOptions = {}) {
    return this.request('PATCH', `/checkpoints/${encodeURIComponent(id)}`, payload, options)
  }

  async deleteCheckpoint(id: string, options: DashboardRequestOptions = {}) {
    return this.request('DELETE', `/checkpoints/${encodeURIComponent(id)}`, undefined, options)
  }

  async listBlacklist(options: DashboardRequestOptions = {}) {
    return this.request('GET', '/blacklist', undefined, options)
  }

  async createBlacklistEntry(payload: BlacklistCreateRequest, options: DashboardRequestOptions = {}) {
    return this.request('POST', '/blacklist', payload, options)
  }

  async deleteBlacklistEntry(id: string, options: DashboardRequestOptions = {}) {
    return this.request('DELETE', `/blacklist/${encodeURIComponent(id)}`, undefined, options)
  }

  async createApiToken(payload: ApiTokenCreateRequest, options: DashboardRequestOptions = {}) {
    return this.request('POST', '/api-tokens', payload, options)
  }

  async updateApiToken(id: string, payload: ApiTokenUpdateRequest, options: DashboardRequestOptions = {}) {
    return this.request('PATCH', `/api-tokens/${encodeURIComponent(id)}`, payload, options)
  }

  async listApiTokens(options: DashboardRequestOptions = {}) {
    return this.request('GET', '/api-tokens', undefined, options)
  }

  async deleteApiToken(id: string, options: DashboardRequestOptions = {}) {
    return this.request('DELETE', `/api-tokens/${encodeURIComponent(id)}`, undefined, options)
  }

  async analyticsSummary(days?: number, options: DashboardRequestOptions = {}) {
    return this.request('GET', '/analytics/summary', undefined, {
      ...options,
      query: days ? { ...(options.query ?? {}), days } : options.query,
    })
  }

  async analyticsGeo(days?: number, options: DashboardRequestOptions = {}) {
    return this.request('GET', '/analytics/geo', undefined, {
      ...options,
      query: days ? { ...(options.query ?? {}), days } : options.query,
    })
  }

  async analyticsActivity(options: DashboardRequestOptions = {}) {
    return this.request('GET', '/analytics/activity', undefined, options)
  }

  async request<T = unknown>(
    method: DashboardHttpMethod,
    path: string,
    body?: unknown,
    options: DashboardRequestOptions = {},
  ): Promise<DashboardResponse<T>> {
    const auth = options.auth ?? this.defaultAuth
    const headers: Record<string, string> = {
      ...(options.headers ?? {}),
    }

    if (auth?.mode === 'session') {
      if (!auth.sessionCookie) {
        throw new Error('sessionCookie is required for session auth mode')
      }
      headers.Cookie = `mc_session=${auth.sessionCookie}`
    }

    if (auth?.mode === 'bearer') {
      if (!auth.bearerToken) {
        throw new Error('bearerToken is required for bearer auth mode')
      }
      headers.Authorization = `Bearer ${auth.bearerToken}`
    }

    const hasBody = method !== 'GET' && body !== undefined
    const bodyString = hasBody ? JSON.stringify(body) : undefined
    if (hasBody) {
      headers['Content-Type'] = 'application/json'
    }

    const url = this.buildUrl(path, options.query)
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this.timeoutMs)

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: bodyString,
        signal: controller.signal,
      })

      const text = await response.text()
      let data: unknown
      try {
        data = text ? JSON.parse(text) : {}
      } catch {
        data = text
      }

      return {
        statusCode: response.status,
        ok: response.ok,
        data: data as T,
        headers: Object.fromEntries(response.headers),
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown request error'
      throw new Error(`NebulAuth dashboard request failed: ${message}`)
    } finally {
      clearTimeout(timer)
    }
  }

  private buildUrl(path: string, query?: Record<string, string | number | boolean | null | undefined>): string {
    const endpoint = path.startsWith('/') ? path : `/${path}`
    const url = new URL(this.baseUrl + endpoint)

    if (query) {
      for (const [key, value] of Object.entries(query)) {
        if (value === undefined || value === null) continue
        url.searchParams.set(key, String(value))
      }
    }

    return url.toString()
  }
}
