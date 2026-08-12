#!/usr/bin/env node
/**
 * Verifies the built-in pktmon capture path end to end. Run this ONCE as
 * Administrator (pktmon needs elevation):
 *
 *   node scripts/test-pktmon.mjs
 *
 * It performs a single ~3 second capture cycle exactly as blazma.nt's pktmon
 * backend does — start, stop, etl2pcap, parse — and reports how many packets
 * were captured and whether the converted file is classic pcap this app can
 * read. It transmits nothing and leaves no capture session running.
 */

import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const PKTMON = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'pktmon.exe')
const run = (args) => spawnSync(PKTMON, args, { encoding: 'utf8', windowsHide: true })

console.log('\nblazma.nt — built-in pktmon capture self-test\n')

// Elevation check.
const who = spawnSync('net', ['session'], { encoding: 'utf8' })
if (who.status !== 0) {
  console.log('  This must run as Administrator. Right-click your terminal → "Run as administrator", then retry.\n')
  process.exit(1)
}

const dir = mkdtempSync(join(tmpdir(), 'blazma-pktmon-test-'))
const etl = join(dir, 'cap.etl')
const pcap = join(dir, 'cap.pcap')
const cleanup = () => {
  run(['stop'])
  rmSync(dir, { recursive: true, force: true })
}

try {
  run(['stop']) // clear any stale session
  console.log('  Capturing for 3 seconds… (generate some traffic — open a website)')
  const started = run(['start', '--capture', '--pkt-size', '512', '--file-name', etl, '--file-size', '512'])
  if (started.status !== 0) {
    console.log(`  [FAIL] pktmon start: ${(started.stderr || started.stdout).trim()}`)
    cleanup()
    process.exit(1)
  }

  await new Promise((r) => setTimeout(r, 3000))
  run(['stop'])

  const conv = run(['etl2pcap', etl, '--out', pcap])
  if (conv.status !== 0) {
    console.log(`  [FAIL] etl2pcap: ${(conv.stderr || conv.stdout).trim()}`)
    cleanup()
    process.exit(1)
  }

  const buf = readFileSync(pcap)
  const magic = buf.readUInt32BE(0)
  const isClassicPcap = [0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1].includes(magic)
  const isPcapng = magic === 0x0a0d0d0a

  // Minimal classic-pcap packet count (16-byte record headers).
  const le = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1
  let count = 0
  let off = 24
  while (off + 16 <= buf.length) {
    const capLen = le ? buf.readUInt32LE(off + 8) : buf.readUInt32BE(off + 8)
    if (capLen <= 0 || capLen > 262144) break
    count++
    off += 16 + capLen
  }

  console.log(`\n  converted file : ${buf.length} bytes`)
  console.log(`  format         : ${isClassicPcap ? 'classic pcap ✓ (blazma.nt can read this)' : isPcapng ? 'pcapng ✗' : `unknown magic 0x${magic.toString(16)}`}`)
  console.log(`  packets parsed : ${count}`)

  if (isClassicPcap && count > 0) {
    console.log('\n  Result: the built-in pktmon engine works on this machine.\n')
  } else if (isClassicPcap) {
    console.log('\n  Format is fine but no packets were captured — try again while browsing.\n')
  } else {
    console.log('\n  This pktmon build does not emit classic pcap; tell the developer the magic value above.\n')
  }
} finally {
  cleanup()
}
