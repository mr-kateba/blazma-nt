import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { app } from 'electron'
import type { CaptureBackendStatus, EnvironmentReport } from '../../shared/types.js'
import { powershell, run } from '../utils/proc.js'

const WIRESHARK_DIRS = [
  'C:\\Program Files\\Wireshark',
  'C:\\Program Files (x86)\\Wireshark',
  join(process.env.LOCALAPPDATA ?? '', 'Programs', 'Wireshark')
]

const NPCAP_MARKERS = [
  'C:\\Windows\\System32\\Npcap\\wpcap.dll',
  'C:\\Windows\\SysWOW64\\Npcap\\wpcap.dll',
  'C:\\Windows\\System32\\wpcap.dll'
]

function findTool(exe: string): string | null {
  for (const dir of WIRESHARK_DIRS) {
    if (!dir) continue
    const candidate = join(dir, exe)
    if (existsSync(candidate)) return candidate
  }
  return null
}

export function npcapInstalled(): boolean {
  return NPCAP_MARKERS.some((p) => existsSync(p))
}

async function npcapVersion(): Promise<string | null> {
  const res = await powershell(
    "$k = Get-ItemProperty 'HKLM:\\SOFTWARE\\WOW6432Node\\Npcap','HKLM:\\SOFTWARE\\Npcap' -ErrorAction SilentlyContinue;" +
      ' if ($k) { ($k | Select-Object -First 1).WinpcapOverride | Out-Null;' +
      " (Get-Item 'C:\\Windows\\System32\\Npcap\\wpcap.dll' -ErrorAction SilentlyContinue).VersionInfo.ProductVersion }",
    8000
  )
  const v = res.stdout.trim()
  return v.length > 0 && v.length < 64 ? v : null
}

export async function isElevated(): Promise<boolean> {
  const res = await powershell(
    '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())' +
      '.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)',
    8000
  )
  return res.stdout.trim().toLowerCase() === 'true'
}

async function toolVersion(path: string): Promise<string | null> {
  const res = await run(path, ['--version'], { timeoutMs: 8000 })
  const first = res.stdout.split('\n')[0]?.trim()
  return first && first.length < 200 ? first : null
}

export async function pktmonAvailable(): Promise<boolean> {
  const exe = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'pktmon.exe')
  return existsSync(exe)
}

/**
 * Probes every capture strategy and reports what this machine can actually do.
 * The UI shows this verbatim so the user is never left guessing why capture is
 * unavailable.
 */
export async function buildEnvironmentReport(): Promise<EnvironmentReport> {
  const dumpcap = findTool('dumpcap.exe')
  const tshark = findTool('tshark.exe')
  const hasNpcap = npcapInstalled()
  const elevated = await isElevated()
  const backends: CaptureBackendStatus[] = []

  backends.push({
    id: 'npcap-dumpcap',
    available: Boolean(dumpcap) && hasNpcap,
    reason: !hasNpcap
      ? 'Npcap is not installed.'
      : !dumpcap
        ? 'dumpcap.exe was not found. Install Wireshark (it bundles dumpcap) or point to it in Settings.'
        : null,
    toolPath: dumpcap,
    version: dumpcap ? await toolVersion(dumpcap) : null,
    requiresElevation: false
  })

  backends.push({
    id: 'npcap-tshark',
    available: Boolean(tshark) && hasNpcap,
    reason: !hasNpcap ? 'Npcap is not installed.' : !tshark ? 'tshark.exe was not found.' : null,
    toolPath: tshark,
    version: tshark ? await toolVersion(tshark) : null,
    requiresElevation: false
  })

  const pktmon = await pktmonAvailable()
  backends.push({
    id: 'pktmon',
    available: pktmon && elevated,
    reason: !pktmon
      ? 'pktmon.exe is not present on this Windows build.'
      : !elevated
        ? 'pktmon requires an elevated (Administrator) process.'
        : null,
    toolPath: pktmon ? join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'pktmon.exe') : null,
    version: null,
    requiresElevation: true
  })

  backends.push({
    id: 'system-only',
    available: true,
    reason:
      'Fallback. Uses Windows connection, ARP and DNS-cache APIs only: devices, connections and byte counters ' +
      'are real, but per-packet protocol analysis, DNS query logging and unencrypted-metadata detection are not available.',
    toolPath: null,
    version: null,
    requiresElevation: false
  })

  const selected = backends.find((b) => b.available && b.id !== 'system-only')?.id ?? 'system-only'

  return {
    npcapInstalled: hasNpcap,
    npcapVersion: hasNpcap ? await npcapVersion() : null,
    elevated,
    backends,
    selectedBackend: selected,
    nodeVersion: process.versions.node,
    electronVersion: process.versions.electron ?? 'unknown',
    platform: `${process.platform} ${process.arch}`
  }
}

export function userDataPath(...segments: string[]): string {
  return join(app.getPath('userData'), ...segments)
}
