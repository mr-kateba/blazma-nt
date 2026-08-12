import { existsSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { networkInterfaces } from 'node:os'
import { join } from 'node:path'
import { app, safeStorage } from 'electron'
import type {
  RouterDevice,
  RouterDnsConfig,
  RouterIdentity,
  RouterStatus
} from '../../shared/router.js'
import { codedError } from '../../shared/errors.js'
import type { EventBus } from '../core/bus.js'
import { normalizeMac } from '../utils/net.js'
import type { Logger } from '../utils/logger.js'
import { detectRouter } from './detect.js'
import { HuaweiApiError, HuaweiClient } from './huaweiClient.js'
import { HuaweiController } from './huaweiController.js'

const SCOPE = 'router'

interface SavedCredentials {
  gatewayIp: string
  username: string
  /** DPAPI-encrypted, base64. Never stored or logged in plaintext. */
  passwordEnc: string
}

/**
 * Owns the router connection and the (encrypted) credentials.
 *
 * Passwords are encrypted at rest with Electron safeStorage, which is backed by
 * Windows DPAPI — tied to the OS user account, readable only on this machine.
 * The plaintext password lives only in memory for the moment it is used to log
 * in, and is never written to disk or the log.
 */
export class RouterManager {
  private identity: RouterIdentity | null = null
  private controller: HuaweiController | null = null
  private state: RouterStatus['state'] = 'disconnected'
  private error: string | null = null

  constructor(
    private readonly bus: EventBus,
    private readonly log: Logger
  ) {}

  /** This machine's own interface MACs, so router devices can be flagged self. */
  private localMacs(): Set<string> {
    const set = new Set<string>()
    for (const entries of Object.values(networkInterfaces())) {
      for (const entry of entries ?? []) {
        const mac = normalizeMac(entry.mac)
        if (mac && mac !== '00:00:00:00:00:00') set.add(mac)
      }
    }
    return set
  }

  private get credentialsPath(): string {
    return join(app.getPath('userData'), 'router-credentials.bin')
  }

  private get hasSavedCredentials(): boolean {
    return existsSync(this.credentialsPath)
  }

  getStatus(): RouterStatus {
    return {
      state: this.state,
      identity: this.identity,
      error: this.error,
      hasSavedCredentials: this.hasSavedCredentials,
      signal: null
    }
  }

  private emit(): void {
    this.bus.emit('router:status', this.getStatus())
  }

  private setState(state: RouterStatus['state'], error: string | null = null): void {
    this.state = state
    this.error = error
    this.emit()
  }

  async detect(): Promise<RouterIdentity | null> {
    this.identity = await detectRouter()
    this.emit()
    return this.identity
  }

  /**
   * Logs in and, when asked, saves the credentials encrypted for reconnecting.
   * The password is used once here and not retained in the manager.
   */
  async connect(username: string, password: string, save: boolean): Promise<RouterStatus> {
    this.setState('connecting')
    try {
      const identity = this.identity ?? (await this.detect())
      if (!identity || !identity.controllable) {
        throw codedError('E_ROUTER_UNSUPPORTED', 'This router is not controllable by blazma.nt.')
      }

      const client = new HuaweiClient(identity.gatewayIp)
      if (identity.loginScheme === 'hashed') await client.loginHashed(username, password)
      else await client.loginScram(username, password)

      this.controller = new HuaweiController(client)
      this.identity = identity
      this.setState('connected')
      this.log.info(SCOPE, `Connected to ${identity.friendlyName ?? identity.model ?? 'router'} at ${identity.gatewayIp}.`)

      if (save) this.saveCredentials(identity.gatewayIp, username, password)
      return this.getStatus()
    } catch (err) {
      const message = err instanceof HuaweiApiError ? err.message : err instanceof Error ? err.message : String(err)
      this.log.error(SCOPE, `Router login failed: ${message}`)
      this.setState('error', message)
      throw codedError('E_ROUTER_LOGIN', message)
    }
  }

  /** Attempts to reconnect from stored credentials, e.g. at startup. */
  async reconnect(): Promise<boolean> {
    const creds = this.loadCredentials()
    if (!creds) return false
    try {
      await this.connect(creds.username, creds.password, false)
      return this.state === 'connected'
    } catch {
      // A silent background attempt must not leave the UI in an alarming error
      // state; fall back to plain disconnected so the user can retry manually.
      this.setState('disconnected')
      return false
    }
  }

  disconnect(): void {
    this.controller = null
    this.setState('disconnected')
  }

  forget(): void {
    this.disconnect()
    try {
      if (this.hasSavedCredentials) rmSync(this.credentialsPath)
    } catch {
      // Nothing to remove.
    }
    this.emit()
  }

  private requireController(): HuaweiController {
    if (!this.controller || this.state !== 'connected') {
      throw codedError('E_ROUTER_NOT_CONNECTED', 'Not connected to the router. Connect first.')
    }
    return this.controller
  }

  async devices(): Promise<RouterDevice[]> {
    return this.requireController().devices(this.localMacs())
  }

  async signal(): Promise<RouterStatus['signal']> {
    return this.requireController().signal()
  }

  async block(mac: string): Promise<void> {
    await this.requireController().block(mac)
    this.log.info(SCOPE, `Blocked device ${mac} via the router MAC filter.`)
  }

  async unblock(mac: string): Promise<void> {
    await this.requireController().unblock(mac)
    this.log.info(SCOPE, `Unblocked device ${mac}.`)
  }

  async getDns(): Promise<RouterDnsConfig> {
    return this.requireController().dns()
  }

  async setDns(primary: string | null, secondary: string | null): Promise<void> {
    await this.requireController().setDns(primary, secondary)
    this.log.info(SCOPE, `Router DNS updated (primary=${primary ?? 'auto'}).`)
  }

  async reboot(): Promise<void> {
    await this.requireController().reboot()
    this.log.warn(SCOPE, 'Router reboot requested by user.')
    this.disconnect()
  }

  /* ---------------------------------------------------------------- */
  /* Credential storage                                                */
  /* ---------------------------------------------------------------- */

  private saveCredentials(gatewayIp: string, username: string, password: string): void {
    if (!safeStorage.isEncryptionAvailable()) {
      this.log.warn(SCOPE, 'OS encryption unavailable; router credentials will not be saved.')
      return
    }
    const passwordEnc = safeStorage.encryptString(password).toString('base64')
    const payload: SavedCredentials = { gatewayIp, username, passwordEnc }
    writeFileSync(this.credentialsPath, JSON.stringify(payload), { encoding: 'utf8', mode: 0o600 })
    this.log.info(SCOPE, 'Router credentials saved (encrypted with the OS keystore).')
  }

  private loadCredentials(): { gatewayIp: string; username: string; password: string } | null {
    if (!this.hasSavedCredentials || !safeStorage.isEncryptionAvailable()) return null
    try {
      const payload = JSON.parse(readFileSync(this.credentialsPath, 'utf8')) as SavedCredentials
      const password = safeStorage.decryptString(Buffer.from(payload.passwordEnc, 'base64'))
      return { gatewayIp: payload.gatewayIp, username: payload.username, password }
    } catch (err) {
      this.log.error(SCOPE, 'Could not read saved router credentials', err)
      return null
    }
  }
}
