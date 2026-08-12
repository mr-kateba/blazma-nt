/**
 * Shared contract for the router-control feature.
 *
 * This is an *active* control surface, unlike the rest of blazma.nt which is
 * passive. Every action here is a command sent to a router the user owns,
 * through that router's own official API — there is no packet injection,
 * spoofing or interception anywhere in this feature.
 */

export type RouterVendor = 'huawei' | 'unknown'

export interface RouterIdentity {
  vendor: RouterVendor
  /** Model reported by the device, e.g. "B628-350". */
  model: string | null
  /** Marketing name, e.g. "4G CPE Pro 3". */
  friendlyName: string | null
  gatewayIp: string
  /** True when blazma.nt has a working control integration for this device. */
  controllable: boolean
  /** How authentication works, so the UI can explain what login is needed. */
  loginScheme: 'scram' | 'hashed' | 'none' | 'unknown'
  /** Human-readable note when not controllable. */
  note: string | null
}

export type RouterConnectionState = 'disconnected' | 'connecting' | 'connected' | 'error'

export interface RouterStatus {
  state: RouterConnectionState
  identity: RouterIdentity | null
  error: string | null
  /** True when credentials are stored (encrypted) for auto-reconnect. */
  hasSavedCredentials: boolean
  signal: RouterSignal | null
}

export interface RouterSignal {
  /** Network type, e.g. "LTE", "4G+", "5G". */
  networkType: string | null
  /** Signal bars 0–5 when the device reports them. */
  bars: number | null
  rsrp: string | null
  rsrq: string | null
  sinr: string | null
  operator: string | null
}

/** A device as the *router* sees it — distinct from blazma's packet view. */
export interface RouterDevice {
  mac: string
  ip: string | null
  hostname: string | null
  /** True when currently associated/online per the router. */
  online: boolean
  /** True when this MAC is on the router's block list. */
  blocked: boolean
  /** 'wifi' | 'ethernet' | 'unknown' as reported. */
  medium: string
  /** True when this is the machine blazma.nt runs on. */
  isSelf: boolean
}

export interface RouterDnsConfig {
  /** True when the router hands out DNS automatically from the carrier. */
  automatic: boolean
  primary: string | null
  secondary: string | null
}

/** What the connected router actually supports, so the UI hides what it can't do. */
export interface RouterCapabilities {
  blockDevices: boolean
  dns: boolean
  reboot: boolean
  deviceList: boolean
  signal: boolean
}
