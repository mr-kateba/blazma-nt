import type { AppSettings } from '../../shared/types.js'
import type { Store } from '../database/store.js'

export const DEFAULT_SETTINGS: AppSettings = {
  interfaceId: null,
  autoStart: false,
  privacyMode: false,
  storeDnsQueries: true,
  storeUnencryptedMetadata: true,
  retention: '7d',
  notificationsEnabled: true,
  notifyMinSeverity: 'MEDIUM',
  theme: 'dark',
  language: 'ar',
  uiUpdateHz: 2,
  maxLiveFlows: 500,
  logLevel: 'INFO',
  telemetry: false
}

const SETTINGS_KEY = 'app-settings'

/** Every field is re-validated on read so a hand-edited DB cannot inject values. */
function coerce(raw: unknown): AppSettings {
  const s = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>
  const pick = <K extends keyof AppSettings>(key: K, allowed: readonly AppSettings[K][]): AppSettings[K] =>
    allowed.includes(s[key] as AppSettings[K]) ? (s[key] as AppSettings[K]) : DEFAULT_SETTINGS[key]

  const bool = (key: keyof AppSettings): boolean =>
    typeof s[key] === 'boolean' ? (s[key] as boolean) : (DEFAULT_SETTINGS[key] as boolean)

  const num = (key: keyof AppSettings, min: number, max: number): number => {
    const v = s[key]
    return typeof v === 'number' && Number.isFinite(v)
      ? Math.min(Math.max(v, min), max)
      : (DEFAULT_SETTINGS[key] as number)
  }

  return {
    interfaceId: typeof s.interfaceId === 'string' && s.interfaceId.length < 512 ? s.interfaceId : null,
    autoStart: bool('autoStart'),
    privacyMode: bool('privacyMode'),
    storeDnsQueries: bool('storeDnsQueries'),
    storeUnencryptedMetadata: bool('storeUnencryptedMetadata'),
    retention: pick('retention', ['1d', '7d', '30d', '90d', 'unlimited']),
    notificationsEnabled: bool('notificationsEnabled'),
    notifyMinSeverity: pick('notifyMinSeverity', ['INFO', 'LOW', 'MEDIUM', 'HIGH']),
    theme: pick('theme', ['dark', 'light', 'system']),
    language: pick('language', ['ar', 'en']),
    uiUpdateHz: num('uiUpdateHz', 1, 10),
    maxLiveFlows: num('maxLiveFlows', 50, 5000),
    logLevel: pick('logLevel', ['DEBUG', 'INFO', 'WARNING', 'ERROR']),
    // Hard-coded: there is no telemetry in this application.
    telemetry: false
  }
}

export class SettingsManager {
  private current: AppSettings

  constructor(private readonly store: Store) {
    const raw = store.getSetting(SETTINGS_KEY)
    let parsed: unknown = {}
    if (raw) {
      try {
        parsed = JSON.parse(raw)
      } catch {
        parsed = {}
      }
    }
    this.current = coerce(parsed)
  }

  get(): AppSettings {
    return { ...this.current }
  }

  update(patch: Partial<AppSettings>): AppSettings {
    this.current = coerce({ ...this.current, ...patch })
    this.store.setSetting(SETTINGS_KEY, JSON.stringify(this.current))
    return this.get()
  }
}
