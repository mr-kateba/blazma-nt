import { normalizeMac } from '../utils/net.js'
import { parsePsJson, powershell } from '../utils/proc.js'

/**
 * Fallback telemetry for machines without Npcap.
 *
 * Honest about its limits: Windows APIs expose *this* computer's sockets, the
 * ARP neighbour table (which reveals other devices on the LAN), the local DNS
 * resolver cache and per-adapter byte counters. They do not expose other
 * devices' traffic, so protocol analysis and unencrypted-payload detection are
 * simply unavailable in this mode — the engine reports that rather than
 * inventing data.
 */

export interface SystemConnection {
  localAddress: string
  localPort: number
  remoteAddress: string
  remotePort: number
  state: string
  transport: 'TCP' | 'UDP'
  processName: string | null
}

export interface SystemNeighbor {
  ip: string
  mac: string | null
  state: string
}

export interface SystemDnsEntry {
  name: string
  type: string
  data: string
  ttl: number
}

export interface AdapterCounters {
  bytesReceived: number
  bytesSent: number
  packetsReceived: number
  packetsSent: number
}

const CONNECTIONS_SCRIPT = `
$tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' } |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
    @{n='Transport';e={'TCP'}}
$udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
  Select-Object LocalAddress, LocalPort, @{n='RemoteAddress';e={''}}, @{n='RemotePort';e={0}},
    @{n='State';e={'STATELESS'}}, OwningProcess, @{n='Transport';e={'UDP'}}
$all = @($tcp) + @($udp)
$procs = @{}
Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
$all | ForEach-Object {
  $_ | Add-Member -NotePropertyName ProcessName -NotePropertyValue $procs[[int]$_.OwningProcess] -Force -PassThru
} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, Transport, ProcessName |
  ConvertTo-Json -Compress -Depth 3
`

const NEIGHBORS_SCRIPT = `
Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.State -ne 'Unreachable' -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } |
  Select-Object @{n='ip';e={$_.IPAddress}}, @{n='mac';e={$_.LinkLayerAddress}}, @{n='state';e={[string]$_.State}} |
  ConvertTo-Json -Compress -Depth 3
`

const DNS_CACHE_SCRIPT = `
Get-DnsClientCache -ErrorAction SilentlyContinue |
  Select-Object @{n='name';e={$_.Entry}}, @{n='type';e={[string]$_.Type}},
    @{n='data';e={$_.Data}}, @{n='ttl';e={[int]$_.TimeToLive}} |
  ConvertTo-Json -Compress -Depth 3
`

export async function pollConnections(): Promise<SystemConnection[]> {
  const res = await powershell(CONNECTIONS_SCRIPT, 25_000)
  return parsePsJson<Record<string, unknown>>(res.stdout)
    .map((r) => ({
      localAddress: String(r.LocalAddress ?? ''),
      localPort: Number(r.LocalPort ?? 0),
      remoteAddress: String(r.RemoteAddress ?? ''),
      remotePort: Number(r.RemotePort ?? 0),
      state: String(r.State ?? 'UNKNOWN'),
      transport: (r.Transport === 'UDP' ? 'UDP' : 'TCP') as 'TCP' | 'UDP',
      processName: r.ProcessName ? String(r.ProcessName) : null
    }))
    .filter((c) => c.localAddress.length > 0)
}

export async function pollNeighbors(): Promise<SystemNeighbor[]> {
  const res = await powershell(NEIGHBORS_SCRIPT, 20_000)
  return parsePsJson<{ ip: string; mac: string; state: string }>(res.stdout).map((r) => ({
    ip: String(r.ip),
    mac: normalizeMac(String(r.mac)),
    state: String(r.state)
  }))
}

export async function pollDnsCache(): Promise<SystemDnsEntry[]> {
  const res = await powershell(DNS_CACHE_SCRIPT, 20_000)
  return parsePsJson<SystemDnsEntry>(res.stdout)
    .map((r) => ({ name: String(r.name ?? ''), type: String(r.type ?? ''), data: String(r.data ?? ''), ttl: Number(r.ttl ?? 0) }))
    .filter((r) => r.name.length > 0)
}

/**
 * Per-adapter byte counters. `Get-NetAdapterStatistics` is keyed by adapter
 * name, which we pass as a bound parameter rather than string-interpolating it
 * into the script.
 */
export async function pollAdapterCounters(adapterName: string): Promise<AdapterCounters | null> {
  const script = `
    param([string]$Name)
    Get-NetAdapterStatistics -Name $Name -ErrorAction SilentlyContinue |
      Select-Object @{n='bytesReceived';e={[int64]$_.ReceivedBytes}},
        @{n='bytesSent';e={[int64]$_.SentBytes}},
        @{n='packetsReceived';e={[int64]$_.ReceivedUnicastPackets + [int64]$_.ReceivedMulticastPackets}},
        @{n='packetsSent';e={[int64]$_.SentUnicastPackets + [int64]$_.SentMulticastPackets}} |
      ConvertTo-Json -Compress
  `
  // Single-quoted PowerShell literal: no expansion of $ or backticks, and any
  // embedded quote is doubled. The name stays data, never code.
  const quoted = `'${adapterName.replace(/'/g, "''")}'`
  const res = await powershell(`& { ${script} } -Name ${quoted}`, 15_000)
  const rows = parsePsJson<AdapterCounters>(res.stdout)
  if (rows.length === 0) return null
  const r = rows[0]
  return {
    bytesReceived: Number(r.bytesReceived ?? 0),
    bytesSent: Number(r.bytesSent ?? 0),
    packetsReceived: Number(r.packetsReceived ?? 0),
    packetsSent: Number(r.packetsSent ?? 0)
  }
}
