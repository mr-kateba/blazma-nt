import { describe, expect, it } from 'vitest'
import { HuaweiController, type HuaweiApi } from '../src/backend/router/huaweiController.js'

/**
 * Exercises the controller's parsing and block-list merge logic against
 * representative Huawei LTE XML, using a fake client. No network, no router.
 */

const HOST_LIST = `<?xml version="1.0" encoding="UTF-8"?>
<response><Hosts>
<Host><HostName>Galaxy-S21</HostName><IpAddress>192.168.8.101</IpAddress>
<MacAddress>AA:BB:CC:DD:EE:01</MacAddress><Active>1</Active><Layer2Interface>SSID1</Layer2Interface></Host>
<Host><HostName>Laptop</HostName><IpAddress>192.168.8.102</IpAddress>
<MacAddress>aa:bb:cc:dd:ee:02</MacAddress><Active>0</Active><Layer2Interface>LAN1</Layer2Interface></Host>
</Hosts></response>`

function macFilterXml(blocked: string[], status = 2): string {
  const macs: string[] = []
  for (let i = 0; i < 10; i++) macs.push(`<WifiMacFilterMac${i}>${blocked[i] ?? ''}</WifiMacFilterMac${i}>`)
  return `<?xml version="1.0" encoding="UTF-8"?><response><Ssids><Ssid>
    <Index>0</Index><wifihostname>MyWiFi</wifihostname>
    <WifiMacFilterStatus>${status}</WifiMacFilterStatus>${macs.join('')}
  </Ssid></Ssids></response>`
}

/** Fake client: routes GET by path, records the last postRaw body. */
class FakeClient implements HuaweiApi {
  lastPostRaw: { path: string; body: string } | null = null
  lastPost: { path: string; fields: Record<string, string | number> } | null = null

  constructor(
    private readonly gets: Record<string, string>,
    private readonly failMulti = false
  ) {}

  async get(path: string): Promise<string> {
    if (path in this.gets) return this.gets[path]
    throw new Error(`unexpected GET ${path}`)
  }
  async post(path: string, fields: Record<string, string | number>): Promise<string> {
    this.lastPost = { path, fields }
    return '<response>OK</response>'
  }
  async postRaw(path: string, body: string): Promise<string> {
    if (this.failMulti && path.includes('multi-macfilter')) throw new Error('unsupported')
    this.lastPostRaw = { path, body }
    return '<response>OK</response>'
  }
}

describe('HuaweiController.devices', () => {
  it('merges the host list with the block list', async () => {
    const client = new FakeClient({
      '/api/wlan/host-list': HOST_LIST,
      '/api/wlan/multi-macfilter-settings': macFilterXml(['aa:bb:cc:dd:ee:02'])
    })
    const devices = await new HuaweiController(client).devices(new Set(['AA:BB:CC:DD:EE:01']))

    expect(devices).toHaveLength(2)
    const byMac = new Map(devices.map((d) => [d.mac, d]))

    const phone = byMac.get('AA:BB:CC:DD:EE:01')!
    expect(phone.online).toBe(true)
    expect(phone.blocked).toBe(false)
    expect(phone.medium).toBe('wifi')
    expect(phone.isSelf).toBe(true)
    expect(phone.hostname).toBe('Galaxy-S21')

    // The blocked laptop MAC was lower-case in both documents; it must still match.
    const laptop = byMac.get('AA:BB:CC:DD:EE:02')!
    expect(laptop.blocked).toBe(true)
    expect(laptop.online).toBe(false)
    expect(laptop.medium).toBe('unknown')
    expect(laptop.isSelf).toBe(false)
  })

  it('still shows a blocked device that dropped off the host list', async () => {
    const client = new FakeClient({
      '/api/wlan/host-list': '<response><Hosts></Hosts></response>',
      '/api/wlan/multi-macfilter-settings': macFilterXml(['11:22:33:44:55:66'])
    })
    const devices = await new HuaweiController(client).devices(new Set())
    expect(devices).toHaveLength(1)
    expect(devices[0].mac).toBe('11:22:33:44:55:66')
    expect(devices[0].blocked).toBe(true)
  })

  it('does not treat an allow-list (status 1) as blocked', async () => {
    const client = new FakeClient({
      '/api/wlan/host-list': HOST_LIST,
      '/api/wlan/multi-macfilter-settings': macFilterXml(['aa:bb:cc:dd:ee:02'], 1)
    })
    const devices = await new HuaweiController(client).devices(new Set())
    expect(devices.every((d) => !d.blocked)).toBe(true)
  })
})

describe('HuaweiController.block / unblock', () => {
  it('adds a MAC to the deny list, preserving existing entries', async () => {
    const client = new FakeClient({
      '/api/wlan/multi-macfilter-settings': macFilterXml(['AA:BB:CC:DD:EE:02'])
    })
    await new HuaweiController(client).block('11:22:33:44:55:66')

    const body = client.lastPostRaw!.body
    expect(client.lastPostRaw!.path).toContain('multi-macfilter')
    expect(body).toContain('<WifiMacFilterStatus>2</WifiMacFilterStatus>')
    expect(body).toContain('<WifiMacFilterMac0>AA:BB:CC:DD:EE:02</WifiMacFilterMac0>')
    expect(body).toContain('<WifiMacFilterMac1>11:22:33:44:55:66</WifiMacFilterMac1>')
  })

  it('removes a MAC and turns the filter off when the list empties', async () => {
    const client = new FakeClient({
      '/api/wlan/multi-macfilter-settings': macFilterXml(['11:22:33:44:55:66'])
    })
    await new HuaweiController(client).unblock('11:22:33:44:55:66')

    const body = client.lastPostRaw!.body
    expect(body).toContain('<WifiMacFilterStatus>0</WifiMacFilterStatus>')
    expect(body).toContain('<WifiMacFilterMac0></WifiMacFilterMac0>')
    expect(body).not.toContain('11:22:33:44:55:66')
  })

  it('falls back to the single-SSID endpoint when multi is unsupported', async () => {
    const client = new FakeClient(
      { '/api/wlan/multi-macfilter-settings': macFilterXml([]), '/api/wlan/mac-filter': macFilterXml([]) },
      true
    )
    await new HuaweiController(client).block('11:22:33:44:55:66')
    expect(client.lastPostRaw!.path).toBe('/api/wlan/mac-filter')
  })

  it('rejects an invalid MAC', async () => {
    const client = new FakeClient({ '/api/wlan/multi-macfilter-settings': macFilterXml([]) })
    await expect(new HuaweiController(client).block('not-a-mac')).rejects.toThrow()
  })
})

describe('HuaweiController.dns / signal / reboot', () => {
  it('reads DNS config', async () => {
    const client = new FakeClient({
      '/api/dhcp/settings':
        '<response><DnsStatus>1</DnsStatus><PrimaryDns>1.1.1.1</PrimaryDns><SecondaryDns>1.0.0.1</SecondaryDns></response>'
    })
    const dns = await new HuaweiController(client).dns()
    expect(dns.automatic).toBe(false)
    expect(dns.primary).toBe('1.1.1.1')
    expect(dns.secondary).toBe('1.0.0.1')
  })

  it('writes DNS while preserving the DHCP scope', async () => {
    const client = new FakeClient({
      '/api/dhcp/settings':
        '<response><DhcpIPAddress>192.168.8.1</DhcpIPAddress><DhcpStartIPAddress>192.168.8.100</DhcpStartIPAddress><DhcpEndIPAddress>192.168.8.200</DhcpEndIPAddress><PrimaryDns>8.8.8.8</PrimaryDns></response>'
    })
    await new HuaweiController(client).setDns('1.1.1.1', '1.0.0.1')
    expect(client.lastPost!.fields.PrimaryDns).toBe('1.1.1.1')
    expect(client.lastPost!.fields.DnsStatus).toBe(1)
    expect(client.lastPost!.fields.DhcpStartIPAddress).toBe('192.168.8.100')
  })

  it('parses the signal', async () => {
    const client = new FakeClient({
      '/api/monitoring/status': '<response><CurrentNetworkType>19</CurrentNetworkType><SignalIcon>4</SignalIcon></response>',
      '/api/device/signal': '<response><rsrp>-95dBm</rsrp><rsrq>-10dB</rsrq><sinr>12dB</sinr></response>'
    })
    const signal = await new HuaweiController(client).signal()
    expect(signal.networkType).toBe('LTE')
    expect(signal.bars).toBe(4)
    expect(signal.rsrp).toBe('-95dBm')
  })

  it('sends the reboot control command', async () => {
    const client = new FakeClient({})
    await new HuaweiController(client).reboot()
    expect(client.lastPost!.path).toBe('/api/device/control')
    expect(client.lastPost!.fields.Control).toBe(1)
  })
})
