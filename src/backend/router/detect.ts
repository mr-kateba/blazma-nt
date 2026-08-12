import type { RouterIdentity } from '../../shared/router.js'
import { parsePsJson, powershell } from '../utils/proc.js'
import { HuaweiClient } from './huaweiClient.js'

/** Finds the default IPv4 gateway, which is the router's LAN address. */
export async function findGateway(): Promise<string | null> {
  const res = await powershell(
    "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | " +
      'Sort-Object RouteMetric | Select-Object -First 1 -Property @{n=\'gw\';e={$_.NextHop}} | ConvertTo-Json -Compress',
    8000
  )
  const rows = parsePsJson<{ gw: string }>(res.stdout)
  const gw = rows[0]?.gw
  return gw && /^\d{1,3}(\.\d{1,3}){3}$/.test(gw) ? gw : null
}

/**
 * Identifies the router at the gateway. Currently recognises Huawei LTE devices
 * (which expose a full local API); anything else is reported as present but not
 * controllable, with an honest note rather than a false promise.
 */
export async function detectRouter(gatewayOverride?: string): Promise<RouterIdentity | null> {
  const gateway = gatewayOverride ?? (await findGateway())
  if (!gateway) return null

  const base: RouterIdentity = {
    vendor: 'unknown',
    model: null,
    friendlyName: null,
    gatewayIp: gateway,
    controllable: false,
    loginScheme: 'unknown',
    note: 'blazma.nt could not identify this router, so remote control is unavailable. Monitoring still works.'
  }

  const client = new HuaweiClient(gateway, 6000)
  try {
    const info = await client.basicInformation()
    if (info.model || info.friendlyName) {
      const state = await client.loginState().catch(() => ({ passwordType: 0, state: -1, username: '' }))
      return {
        vendor: 'huawei',
        model: info.model,
        friendlyName: info.friendlyName,
        gatewayIp: gateway,
        controllable: true,
        loginScheme: state.passwordType >= 3 ? 'scram' : state.passwordType > 0 ? 'hashed' : 'scram',
        note: null
      }
    }
  } catch {
    // Not a Huawei device, or its API is not reachable.
  }

  return base
}
