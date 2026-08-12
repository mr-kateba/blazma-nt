import { networkInterfaces } from 'node:os'
import type { NetworkInterfaceInfo } from '../../shared/types.js'
import { normalizeMac } from '../utils/net.js'
import { parsePsJson, powershell, run } from '../utils/proc.js'

interface PsAdapter {
  Name: string
  InterfaceDescription: string
  InterfaceGuid: string | null
  MacAddress: string | null
  Status: string
  LinkSpeed: number | null
  Virtual: boolean | null
}

interface PsConfig {
  InterfaceAlias: string
  IPv4Address: string | null
  IPv4Prefix: number | null
  IPv6Address: string | null
  Gateway: string | null
}

const ADAPTER_SCRIPT = `
Get-NetAdapter -IncludeHidden |
  Select-Object Name, InterfaceDescription, InterfaceGuid, MacAddress, Status,
    @{n='LinkSpeed';e={ [int64]$_.Speed }},
    @{n='Virtual';e={ [bool]$_.Virtual }} |
  ConvertTo-Json -Compress -Depth 3
`

const CONFIG_SCRIPT = `
Get-NetIPConfiguration -All -Detailed |
  Select-Object InterfaceAlias,
    @{n='IPv4Address';e={ ($_.IPv4Address | Select-Object -First 1).IPAddress }},
    @{n='IPv4Prefix';e={ ($_.IPv4Address | Select-Object -First 1).PrefixLength }},
    @{n='IPv6Address';e={ ($_.IPv6Address | Select-Object -First 1).IPAddress }},
    @{n='Gateway';e={ ($_.IPv4DefaultGateway | Select-Object -First 1).NextHop }} |
  ConvertTo-Json -Compress -Depth 3
`

/**
 * Maps Npcap capture device names (\Device\NPF_{GUID}) to adapter GUIDs by
 * running `dumpcap -D`. Without Npcap this returns an empty map and every
 * adapter is reported as not capturable.
 */
export async function npcapDeviceMap(dumpcapPath: string | null): Promise<Map<string, string>> {
  const map = new Map<string, string>()
  if (!dumpcapPath) return map
  const res = await run(dumpcapPath, ['-D'], { timeoutMs: 15_000 })
  for (const line of res.stdout.split(/\r?\n/)) {
    // Example: "1. \Device\NPF_{6C2A...} (Wi-Fi)"
    const match = line.match(/(\\Device\\NPF_\{[0-9A-Fa-f-]+\})/)
    if (!match) continue
    const device = match[1]
    const guid = device.slice(device.indexOf('{'))
    map.set(guid.toUpperCase(), device)
  }
  return map
}

export async function listInterfaces(dumpcapPath: string | null): Promise<NetworkInterfaceInfo[]> {
  const [adapterRes, configRes, deviceMap] = await Promise.all([
    powershell(ADAPTER_SCRIPT),
    powershell(CONFIG_SCRIPT),
    npcapDeviceMap(dumpcapPath)
  ])

  const adapters = parsePsJson<PsAdapter>(adapterRes.stdout)
  const configs = parsePsJson<PsConfig>(configRes.stdout)
  const configByAlias = new Map(configs.map((c) => [c.InterfaceAlias, c]))
  const osIfaces = networkInterfaces()

  const out: NetworkInterfaceInfo[] = []

  for (const a of adapters) {
    const cfg = configByAlias.get(a.Name)
    const osEntries = osIfaces[a.Name] ?? []
    const ipv4 = new Set<string>()
    const ipv6 = new Set<string>()
    for (const e of osEntries) {
      if (e.family === 'IPv4') ipv4.add(e.address)
      else ipv6.add(e.address)
    }
    if (cfg?.IPv4Address) ipv4.add(cfg.IPv4Address)
    if (cfg?.IPv6Address) ipv6.add(cfg.IPv6Address)

    const guid = a.InterfaceGuid?.toUpperCase() ?? null
    const npcapDevice = guid ? (deviceMap.get(guid) ?? null) : null
    const description = a.InterfaceDescription ?? ''
    const isVirtual =
      Boolean(a.Virtual) ||
      /virtual|vmware|hyper-v|loopback|vbox|tap|tun|wintun|wireguard|npcap/i.test(description)

    out.push({
      id: npcapDevice ?? `alias:${a.Name}`,
      name: a.Name,
      description,
      ipv4: [...ipv4],
      ipv6: [...ipv6],
      mac: normalizeMac(a.MacAddress),
      gateway: cfg?.Gateway ?? null,
      status: a.Status ?? 'Unknown',
      speedBps: a.LinkSpeed && a.LinkSpeed > 0 ? Number(a.LinkSpeed) : null,
      prefixLength: cfg?.IPv4Prefix ?? null,
      isLoopback: /loopback/i.test(description) || /loopback/i.test(a.Name),
      isVirtual,
      capturable: npcapDevice !== null
    })
  }

  // If PowerShell was unavailable for any reason, still show what Node knows so
  // the UI is never empty.
  if (out.length === 0) {
    for (const [name, entries] of Object.entries(osIfaces)) {
      if (!entries) continue
      out.push({
        id: `alias:${name}`,
        name,
        description: name,
        ipv4: entries.filter((e) => e.family === 'IPv4').map((e) => e.address),
        ipv6: entries.filter((e) => e.family === 'IPv6').map((e) => e.address),
        mac: normalizeMac(entries[0]?.mac ?? null),
        gateway: null,
        status: 'Unknown',
        speedBps: null,
        prefixLength: null,
        isLoopback: entries.some((e) => e.internal),
        isVirtual: false,
        capturable: false
      })
    }
  }

  out.sort((a, b) => {
    if (a.capturable !== b.capturable) return a.capturable ? -1 : 1
    if (a.isVirtual !== b.isVirtual) return a.isVirtual ? 1 : -1
    return a.name.localeCompare(b.name)
  })

  return out
}
