import { clientNonce, hashedPassword, scramClientProof } from './huaweiCrypto.js'

/**
 * Minimal client for the Huawei LTE web API (the same API the router's own
 * browser UI uses). Talks plain HTTP to the gateway on the LAN; nothing here
 * reaches the internet.
 *
 * Responses are XML. A tiny purpose-built parser is used rather than a
 * dependency, since the documents are small and flat.
 */

export interface HuaweiError {
  code: string
  message: string
}

export class HuaweiApiError extends Error {
  constructor(
    readonly apiCode: string,
    message: string
  ) {
    super(message)
    this.name = 'HuaweiApiError'
  }
}

/** Maps the most common Huawei error codes to readable text. */
const ERROR_TEXT: Record<string, string> = {
  '100002': 'The router does not support this operation.',
  '100003': 'Not authorised — login required.',
  '100004': 'The router is busy; try again.',
  '108001': 'Incorrect username.',
  '108002': 'Incorrect password.',
  '108003': 'Already logged in elsewhere.',
  '108006': 'Incorrect username or password.',
  '108007': 'Too many failed attempts; the router is temporarily locked.',
  '125001': 'Wrong session token.',
  '125002': 'Wrong session; reconnect.',
  '125003': 'Wrong verification token.'
}

export function huaweiErrorText(code: string): string {
  return ERROR_TEXT[code] ?? `Router error ${code}.`
}

/* ------------------------------------------------------------------ */
/* Tiny XML helpers                                                    */
/* ------------------------------------------------------------------ */

/** Extracts the text of the first <tag> … </tag>. Flat documents only. */
export function xmlTag(xml: string, tag: string): string | null {
  const match = xml.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, 'i'))
  return match ? decodeXml(match[1].trim()) : null
}

/** Returns every occurrence of a repeated element as raw inner XML. */
export function xmlList(xml: string, tag: string): string[] {
  const out: string[] = []
  const re = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, 'gi')
  let m: RegExpExecArray | null
  while ((m = re.exec(xml)) !== null) out.push(m[1])
  return out
}

function decodeXml(text: string): string {
  return text
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&')
}

function encodeXml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/** Builds a Huawei <request> body from flat key/value pairs. */
export function buildRequest(fields: Record<string, string | number>): string {
  const inner = Object.entries(fields)
    .map(([k, v]) => `<${k}>${encodeXml(String(v))}</${k}>`)
    .join('')
  return `<?xml version="1.0" encoding="UTF-8"?><request>${inner}</request>`
}

function parseError(xml: string): HuaweiError | null {
  if (!/<error>/i.test(xml)) return null
  return { code: xmlTag(xml, 'code') ?? 'unknown', message: xmlTag(xml, 'message') ?? '' }
}

/* ------------------------------------------------------------------ */
/* Client                                                              */
/* ------------------------------------------------------------------ */

export interface HuaweiSession {
  cookie: string
  requestToken: string
}

export class HuaweiClient {
  private readonly base: string
  private cookie: string | null = null
  /** Rolling verification tokens; each write consumes one. */
  private tokens: string[] = []
  private singleToken: string | null = null

  constructor(
    gatewayIp: string,
    private readonly timeoutMs = 10_000
  ) {
    this.base = `http://${gatewayIp}`
  }

  /**
   * Serializes every request. Huawei sessions are single-threaded and
   * token-based; two requests in flight at once can invalidate each other's
   * session or consume the wrong one-time token. Chaining on `queue` guarantees
   * one request completes before the next starts, which is how the router's own
   * web UI behaves.
   */
  private queue: Promise<unknown> = Promise.resolve()

  private request(
    path: string,
    options: { method?: 'GET' | 'POST'; body?: string; token?: string } = {}
  ): Promise<{ status: number; text: string; headers: Headers }> {
    const run = (): Promise<{ status: number; text: string; headers: Headers }> => this.doRequest(path, options)
    const result = this.queue.then(run, run)
    // Keep the chain alive even if a request rejects.
    this.queue = result.then(
      () => undefined,
      () => undefined
    )
    return result
  }

  private async doRequest(
    path: string,
    options: { method?: 'GET' | 'POST'; body?: string; token?: string }
  ): Promise<{ status: number; text: string; headers: Headers }> {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this.timeoutMs)
    try {
      const headers: Record<string, string> = {
        Accept: 'application/xml, text/html, */*',
        'X-Requested-With': 'XMLHttpRequest'
      }
      if (this.cookie) headers.Cookie = this.cookie
      if (options.body) headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
      if (options.token) headers.__RequestVerificationToken = options.token

      const res = await fetch(`${this.base}${path}`, {
        method: options.method ?? 'GET',
        headers,
        body: options.body,
        signal: controller.signal,
        redirect: 'manual'
      })
      const text = await res.text()
      return { status: res.status, text, headers: res.headers }
    } finally {
      clearTimeout(timer)
    }
  }

  /** Reads device identity. Works without login. */
  async basicInformation(): Promise<{ model: string | null; friendlyName: string | null }> {
    const { text } = await this.request('/api/device/basic_information')
    return { model: xmlTag(text, 'devicename'), friendlyName: xmlTag(text, 'spreadname_en') }
  }

  async loginState(): Promise<{ state: number; passwordType: number; username: string }> {
    const { text } = await this.request('/api/user/state-login')
    return {
      state: Number(xmlTag(text, 'State') ?? '-1'),
      passwordType: Number(xmlTag(text, 'password_type') ?? '0'),
      username: xmlTag(text, 'username') ?? ''
    }
  }

  /**
   * Reads the SessionID from a response. Huawei sends it inconsistently — via a
   * Set-Cookie header on some calls and only in the XML body (<SesInfo>) on
   * others — so both are checked, header first.
   */
  private cookieFromResponse(text: string, headers: Headers): string | null {
    const setCookie = headers.getSetCookie?.() ?? []
    const headerCookie = setCookie.find((c) => c.startsWith('SessionID=')) ?? headers.get('set-cookie')
    if (headerCookie && headerCookie.includes('SessionID=')) return headerCookie.split(';')[0]
    const body = xmlTag(text, 'SesInfo')
    return body ? `SessionID=${body}` : null
  }

  /** Fetches a fresh session cookie and verification token. */
  private async refreshSession(): Promise<void> {
    const { text, headers } = await this.request('/api/webserver/SesTokInfo')
    this.cookie = this.cookieFromResponse(text, headers) ?? this.cookie
    const token = xmlTag(text, 'TokInfo')
    if (token) this.singleToken = token
  }

  private nextToken(): string | undefined {
    if (this.tokens.length > 0) return this.tokens.shift()
    return this.singleToken ?? undefined
  }

  private storeTokens(text: string, headers: Headers): void {
    // After login the router returns a batch of one-time tokens.
    const multi = headers.get('__requestverificationtoken')
    if (multi) {
      this.tokens = multi.split('#').filter(Boolean)
      this.singleToken = this.tokens[0] ?? this.singleToken
    }
    const cookie = this.cookieFromResponse(text, headers)
    if (cookie) this.cookie = cookie
  }

  /**
   * Logs in using SCRAM (password_type 3/4). Returns nothing on success and
   * throws HuaweiApiError on failure so the caller can show a precise reason.
   */
  async loginScram(username: string, password: string): Promise<void> {
    await this.refreshSession()

    const nonce = clientNonce()
    const challenge = await this.request('/api/user/challenge_login', {
      method: 'POST',
      body: buildRequest({ username, firstnonce: nonce, mode: 1 }),
      token: this.singleToken ?? undefined
    })
    // The challenge response carries the next token in its header.
    const challengeToken = challenge.headers.get('__requestverificationtoken')
    if (challengeToken) this.singleToken = challengeToken.split('#')[0]

    const err = parseError(challenge.text)
    if (err) throw new HuaweiApiError(err.code, huaweiErrorText(err.code))

    const salt = xmlTag(challenge.text, 'salt')
    const servernonce = xmlTag(challenge.text, 'servernonce')
    const iterations = Number(xmlTag(challenge.text, 'iterations') ?? '0')
    if (!salt || !servernonce || !iterations) {
      throw new HuaweiApiError('scram', 'Router did not return a valid login challenge.')
    }

    const proof = scramClientProof(nonce, servernonce, password, salt, iterations)
    const auth = await this.request('/api/user/authentication_login', {
      method: 'POST',
      body: buildRequest({ clientproof: proof, finalnonce: servernonce }),
      token: this.singleToken ?? undefined
    })

    const authErr = parseError(auth.text)
    if (authErr) throw new HuaweiApiError(authErr.code, huaweiErrorText(authErr.code))
    this.storeTokens(auth.text, auth.headers)
  }

  /** Logs in using the older hashed scheme (password_type < 3). */
  async loginHashed(username: string, password: string): Promise<void> {
    await this.refreshSession()
    const token = this.singleToken ?? ''
    const body = buildRequest({
      Username: username,
      Password: hashedPassword(username, password, token),
      password_type: 4
    })
    const res = await this.request('/api/user/login', { method: 'POST', body, token })
    const err = parseError(res.text)
    if (err) throw new HuaweiApiError(err.code, huaweiErrorText(err.code))
    this.storeTokens(res.text, res.headers)
  }

  /** GET an authenticated endpoint and return its XML. */
  async get(path: string): Promise<string> {
    const { text } = await this.request(path)
    const err = parseError(text)
    if (err) throw new HuaweiApiError(err.code, huaweiErrorText(err.code))
    return text
  }

  /**
   * POST an authenticated command. Refreshes the session token first and
   * retries once on a token error, which the router raises when a one-time
   * token has already been spent.
   */
  async post(path: string, fields: Record<string, string | number>): Promise<string> {
    const send = async (): Promise<{ text: string; headers: Headers }> => {
      const res = await this.request(path, {
        method: 'POST',
        body: buildRequest(fields),
        token: this.nextToken()
      })
      this.storeTokens(res.text, res.headers)
      return res
    }

    let { text } = await send()
    let err = parseError(text)
    if (err && (err.code === '125001' || err.code === '125002' || err.code === '125003')) {
      await this.refreshSession()
      ;({ text } = await send())
      err = parseError(text)
    }
    if (err) throw new HuaweiApiError(err.code, huaweiErrorText(err.code))
    return text
  }

  /**
   * POSTs a pre-built <request> body for endpoints whose payload is nested and
   * cannot be expressed as flat key/value pairs (e.g. the MAC filter). The same
   * token refresh and one-retry logic as post() applies.
   */
  async postRaw(path: string, innerXml: string): Promise<string> {
    const body = `<?xml version="1.0" encoding="UTF-8"?><request>${innerXml}</request>`
    const send = async (): Promise<{ text: string; headers: Headers }> => {
      const res = await this.request(path, { method: 'POST', body, token: this.nextToken() })
      this.storeTokens(res.text, res.headers)
      return res
    }
    let { text } = await send()
    let err = parseError(text)
    if (err && (err.code === '125001' || err.code === '125002' || err.code === '125003')) {
      await this.refreshSession()
      ;({ text } = await send())
      err = parseError(text)
    }
    if (err) throw new HuaweiApiError(err.code, huaweiErrorText(err.code))
    return text
  }

  get isAuthenticated(): boolean {
    return this.cookie !== null
  }
}

export { encodeXml as encodeHuaweiXml }
