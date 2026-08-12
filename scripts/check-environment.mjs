#!/usr/bin/env node
/**
 * Reports whether this machine can capture, without launching the app.
 * Useful when diagnosing a "capture unavailable" report from a user.
 *
 *   node scripts/check-environment.mjs
 */

import { existsSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'

const NPCAP_MARKERS = [
  'C:\\Windows\\System32\\Npcap\\wpcap.dll',
  'C:\\Windows\\SysWOW64\\Npcap\\wpcap.dll',
  'C:\\Windows\\System32\\wpcap.dll'
]

const WIRESHARK_DIRS = [
  'C:\\Program Files\\Wireshark',
  'C:\\Program Files (x86)\\Wireshark',
  join(process.env.LOCALAPPDATA ?? '', 'Programs', 'Wireshark')
]

const ok = (label, detail = '') => console.log(`  [ok]   ${label}${detail ? ` — ${detail}` : ''}`)
const bad = (label, detail = '') => console.log(`  [MISS] ${label}${detail ? ` — ${detail}` : ''}`)

console.log('\nblazma.nt — capture environment\n')

const npcap = NPCAP_MARKERS.find((p) => existsSync(p))
if (npcap) ok('Npcap', npcap)
else bad('Npcap', 'install from https://npcap.com/#download with WinPcap API-compatible mode')

const dumpcap = WIRESHARK_DIRS.filter(Boolean)
  .map((dir) => join(dir, 'dumpcap.exe'))
  .find((p) => existsSync(p))

if (dumpcap) {
  ok('dumpcap', dumpcap)
  try {
    const version = execFileSync(dumpcap, ['--version'], { encoding: 'utf8', timeout: 8000 }).split('\n')[0]
    console.log(`         ${version.trim()}`)
  } catch {
    console.log('         (version query failed)')
  }
} else {
  bad('dumpcap', 'install Wireshark from https://www.wireshark.org/download.html')
}

if (dumpcap && npcap) {
  console.log('\n  Capture devices:')
  try {
    const devices = execFileSync(dumpcap, ['-D'], { encoding: 'utf8', timeout: 15000 })
    const lines = devices.split(/\r?\n/).filter((l) => l.trim())
    if (lines.length === 0) console.log('    (none — is the Npcap driver running?)')
    for (const line of lines) console.log(`    ${line}`)
  } catch (err) {
    console.log(`    failed: ${err.message}`)
  }
}

console.log(`\n  Node ${process.version} · ${process.platform} ${process.arch}\n`)
// The built-in Windows fallback: pktmon needs no install, only elevation.
const pktmon = existsSync(join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'pktmon.exe'))
console.log(`\n  Built-in fallback (no install):`)
if (pktmon) ok('pktmon', 'Windows built-in — run blazma.nt as Administrator to use it without Npcap')
else bad('pktmon', 'not present on this Windows build')

console.log()
if (npcap && dumpcap) {
  console.log('  Ready: high-performance live capture (Npcap) is available.\n')
} else if (pktmon) {
  console.log('  Ready: no Npcap, but the built-in pktmon engine works if you run blazma.nt as Administrator.')
  console.log('  Verify it with:  node scripts/test-pktmon.mjs   (as Administrator)\n')
} else {
  console.log('  No capture backend available.\n')
}
