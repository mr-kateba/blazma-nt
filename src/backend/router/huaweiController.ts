import type { RouterCapabilities, RouterDevice, RouterDnsConfig, RouterSignal } from '../../shared/router.js'
import { normalizeMac } from '../utils/net.js'
import { xmlList, xmlTag } from './huaweiClient.js'

/**
 * The subset of the Huawei client the controller needs. Depending on this
 * structural type (rather than the concrete class) lets the parsing logic be
 * unit tested with canned XML — HuaweiClient satisfies it as-is.
 */
export interface HuaweiApi {
  get(path: string): Promise<string>
  post(path: string, fields: Record<string, string | number>): Promise<string>
  postRaw(path: string, innerXml: string): Promise<string>
}

/**
 * Turns the Huawei LTE API into blazma.nt's vendor-neutral router model.
 *
 * All control actions go through the router's own API. The block mechanism is
 * the router's built-in WLAN MAC filter, i.e. the same feature exposed in its
 * web UI — the device is told to refuse that MAC. Nothing is spoofed and no
 * traffic is injected.
 */
export class HuaweiController {
  constructor(private readonly client: HuaweiApi) {}

  readonly capabilities: RouterCapabilities = {
    blockDevices: true,
    dns: true,
    reboot: true,
    deviceList: true,
    signal: true
  }

  /* ---------------------------------------------------------------- */
  /* Signal / status                                                   */
  /* ---------------------------------------------------------------- */

  async signal(): Promise<RouterSignal> {
    // Requests are issued one at a time (the client serializes them). The first
    // two endpoints work with only a session; device/signal additionally needs
    // login and supplies the radio metrics, so it is best-effort.
    const status = await this.client.get('/api/monitoring/status').catch(() => '')
    const plmn = await this.client.get('/api/net/current-plmn').catch(() => '')
    const signal = await this.client.get('/api/device/signal').catch(() => '')

    const netType = xmlTag(status, 'CurrentNetworkTypeEx') ?? xmlTag(status, 'CurrentNetworkType')
    const rat = xmlTag(plmn, 'Rat')
    const bars = xmlTag(status, 'SignalIcon')

    return {
      networkType:
        NETWORK_TYPES[netType ?? ''] ??
        RAT_TYPES[rat ?? ''] ??
        (netType ? `type ${netType}` : null),
      bars: bars ? Number(bars) : null,
      rsrp: xmlTag(signal, 'rsrp'),
      rsrq: xmlTag(signal, 'rsrq'),
      sinr: xmlTag(signal, 'sinr'),
      operator: xmlTag(plmn, 'FullName') ?? xmlTag(plmn, 'ShortName')
    }
  }

  /* ---------------------------------------------------------------- */
  /* Device list                                                       */
  /* ---------------------------------------------------------------- */

  /**
   * Lists devices as the router sees them, merged with the block list.
   * `selfMacs` are this machine's own interface MACs, so the UI can flag the
   * device the user is sitting at and warn before it cuts its own connection.
   */
  async devices(selfMacs: Set<string>): Promise<RouterDevice[]> {
    const [hostsXml, blocked] = await Promise.all([this.hostListXml(), this.blockedMacs()])
    const devices = new Map<string, RouterDevice>()

    for (const host of xmlList(hostsXml, 'Host')) {
      const mac = normalizeMac(xmlTag(host, 'MacAddress'))
      if (!mac) continue
      const active = xmlTag(host, 'Active')
      devices.set(mac, {
        mac,
        ip: xmlTag(host, 'IpAddress'),
        hostname: xmlTag(host, 'HostName') || xmlTag(host, 'ActualName'),
        online: active === null ? true : active === '1' || active.toLowerCase() === 'true',
        blocked: blocked.has(mac),
        medium: (xmlTag(host, 'Layer2Interface') ?? '').includes('SSID') ? 'wifi' : 'unknown',
        isSelf: selfMacs.has(mac)
      })
    }

    // A blocked device may not appear in the host list (it is denied), so make
    // sure every blocked MAC is still shown so it can be unblocked.
    for (const mac of blocked) {
      if (!devices.has(mac)) {
        devices.set(mac, {
          mac,
          ip: null,
          hostname: null,
          online: false,
          blocked: true,
          medium: 'wifi',
          isSelf: selfMacs.has(mac)
        })
      }
    }

    return [...devices.values()].sort((a, b) => {
      if (a.online !== b.online) return a.online ? -1 : 1
      return (a.hostname ?? a.mac).localeCompare(b.hostname ?? b.mac)
    })
  }

  private async hostListXml(): Promise<string> {
    // wlan/host-list is the most widely supported; lan/HostInfo is the fallback.
    try {
      return await this.client.get('/api/wlan/host-list')
    } catch {
      return this.client.get('/api/lan/HostInfo').catch(() => '<response></response>')
    }
  }

  /* ---------------------------------------------------------------- */
  /* Block / unblock via the WLAN MAC filter                           */
  /* ---------------------------------------------------------------- */

  private async filterXml(): Promise<string> {
    try {
      return await this.client.get('/api/wlan/multi-macfilter-settings')
    } catch {
      return this.client.get('/api/wlan/mac-filter').catch(() => '<response></response>')
    }
  }

  private async blockedMacs(): Promise<Set<string>> {
    const xml = await this.filterXml()
    const out = new Set<string>()
    // Multi-SSID form: several <Ssid> blocks, each with WifiMacFilterMac0..9 and
    // a status where 2 == blacklist (deny). Only deny lists count as blocks.
    const ssids = xmlList(xml, 'Ssid')
    const scan = (block: string): void => {
      const status = xmlTag(block, 'WifiMacFilterStatus') ?? xmlTag(block, 'wifimacfilterstatus')
      if (status !== '2') return
      for (let i = 0; i < 10; i++) {
        const mac = normalizeMac(xmlTag(block, `WifiMacFilterMac${i}`))
        if (mac) out.add(mac)
      }
    }
    if (ssids.length > 0) ssids.forEach(scan)
    else scan(xml)
    return out
  }

  async block(mac: string): Promise<void> {
    await this.setBlocked(mac, true)
  }

  async unblock(mac: string): Promise<void> {
    await this.setBlocked(mac, false)
  }

  /**
   * Rewrites the MAC filter so `mac` is present (block) or absent (unblock),
   * preserving every other entry. Only the first SSID's filter is used as the
   * block list, which the router applies to that WLAN.
   */
  private async setBlocked(macRaw: string, blocked: boolean): Promise<void> {
    const mac = normalizeMac(macRaw)
    if (!mac) throw new Error('Invalid MAC address.')

    const current = await this.blockedMacs()
    if (blocked) current.add(mac)
    else current.delete(mac)

    const macs = [...current].slice(0, 10)
    const status = macs.length > 0 ? 2 : 0 // 2 = blacklist, 0 = filter off

    const macFields: string[] = []
    for (let i = 0; i < 10; i++) {
      macFields.push(`<WifiMacFilterMac${i}>${macs[i] ?? ''}</WifiMacFilterMac${i}>`)
    }

    // Apply to SSID index 0 (the primary WLAN).
    const inner =
      `<Ssids><Ssid><Index>0</Index>` +
      `<WifiMacFilterStatus>${status}</WifiMacFilterStatus>` +
      macFields.join('') +
      `</Ssid></Ssids>`

    try {
      await this.client.postRaw('/api/wlan/multi-macfilter-settings', inner)
    } catch {
      // Older single-SSID firmwares use a flatter endpoint.
      const flat =
        `<policy>${status}</policy>` + macFields.map((f) => f.replace('WifiMacFilter', 'Wifi')).join('')
      await this.client.postRaw('/api/wlan/mac-filter', flat)
    }
  }

  /* ---------------------------------------------------------------- */
  /* DNS                                                               */
  /* ---------------------------------------------------------------- */

  async dns(): Promise<RouterDnsConfig> {
    const xml = await this.client.get('/api/dhcp/settings').catch(() => '')
    const primary = xmlTag(xml, 'PrimaryDns')
    const secondary = xmlTag(xml, 'SecondaryDns')
    const status = xmlTag(xml, 'DnsStatus')
    return {
      automatic: status === '0' || status === null,
      primary: primary || null,
      secondary: secondary || null
    }
  }

  /** Sets DNS on the DHCP scope, preserving the rest of the DHCP settings. */
  async setDns(primary: string | null, secondary: string | null): Promise<void> {
    const xml = await this.client.get('/api/dhcp/settings')
    const keep = (tag: string, fallback = ''): string => xmlTag(xml, tag) ?? fallback
    const manual = primary ? 1 : 0

    await this.client.post('/api/dhcp/settings', {
      DhcpIPAddress: keep('DhcpIPAddress', '192.168.8.1'),
      DhcpLanNetmask: keep('DhcpLanNetmask', '255.255.255.0'),
      DhcpStatus: keep('DhcpStatus', '1'),
      DhcpStartIPAddress: keep('DhcpStartIPAddress', '192.168.8.100'),
      DhcpEndIPAddress: keep('DhcpEndIPAddress', '192.168.8.200'),
      DhcpLeaseTime: keep('DhcpLeaseTime', '86400'),
      DnsStatus: manual,
      PrimaryDns: primary ?? keep('PrimaryDns'),
      SecondaryDns: secondary ?? keep('SecondaryDns')
    })
  }

  /* ---------------------------------------------------------------- */
  /* Reboot                                                            */
  /* ---------------------------------------------------------------- */

  async reboot(): Promise<void> {
    await this.client.post('/api/device/control', { Control: 1 })
  }
}

/** Rat values from /api/net/current-plmn (radio access technology). */
const RAT_TYPES: Record<string, string> = {
  '0': 'GSM',
  '2': '3G (UMTS)',
  '7': 'LTE',
  '8': 'LTE',
  '9': '5G'
}

const NETWORK_TYPES: Record<string, string> = {
  '0': 'No service',
  '1': 'GSM',
  '2': 'GPRS',
  '3': 'EDGE',
  '4': 'WCDMA',
  '5': 'HSDPA',
  '6': 'HSUPA',
  '7': 'HSPA',
  '9': 'HSPA+',
  '19': 'LTE',
  '41': 'UMTS',
  '44': 'HSPA',
  '45': 'HSPA+',
  '46': 'DC-HSPA+',
  '64': 'HSPA',
  '65': 'HSPA+',
  '101': 'LTE',
  '111': '5G',
  '1011': 'LTE'
}
