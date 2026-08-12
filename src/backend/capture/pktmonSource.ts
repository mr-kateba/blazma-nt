import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { CaptureBackendId } from '../../shared/types.js'
import { run } from '../utils/proc.js'
import { PcapStreamReader } from './pcapStream.js'
import type { CaptureSource, CaptureSourceEvents } from './source.js'

export interface PktmonOptions {
  /** Path to pktmon.exe; defaults to the System32 copy. */
  toolPath?: string
  /** Bytes captured per frame. */
  snapLength?: number
  /**
   * Length of each capture cycle in ms. pktmon is file-based, so it is captured
   * in short segments and converted between them — this trades a few seconds of
   * latency for needing no external capture driver at all.
   */
  cycleMs?: number
}

const DEFAULT_PKTMON = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'pktmon.exe')

/**
 * Capture backend built on Windows' built-in pktmon — no Npcap, no external
 * download, nothing to bundle. It requires an elevated process (the pktmon
 * driver refuses non-administrators) and is strictly read-only: pktmon only
 * observes, it never transmits.
 *
 * pktmon writes ETL files rather than streaming, so this runs a start → capture
 * → stop → convert → parse loop, feeding each converted pcap segment through the
 * same PcapStreamReader and parser the live dumpcap backend uses.
 */
export class PktmonSource implements CaptureSource {
  readonly id: CaptureBackendId = 'pktmon'

  private readonly toolPath: string
  private readonly snapLength: number
  private readonly cycleMs: number
  private stopped = false
  private looping = false
  private workDir: string | null = null

  constructor(options: PktmonOptions = {}) {
    this.toolPath = options.toolPath ?? DEFAULT_PKTMON
    this.snapLength = Math.min(Math.max(options.snapLength ?? 512, 96), 65535)
    this.cycleMs = Math.min(Math.max(options.cycleMs ?? 2500, 1000), 10_000)
  }

  get running(): boolean {
    return this.looping && !this.stopped
  }

  async start(events: CaptureSourceEvents): Promise<void> {
    // Clear any capture session left running by a previous crash.
    await run(this.toolPath, ['stop'], { timeoutMs: 8000 }).catch(() => undefined)

    // A probe start/stop surfaces "access denied" immediately rather than after
    // the first silent cycle, so the UI can tell the user to run as admin.
    this.workDir = mkdtempSync(join(tmpdir(), 'blazma-pktmon-'))
    const probeEtl = join(this.workDir, 'probe.etl')
    const probe = await run(
      this.toolPath,
      ['start', '--capture', '--pkt-size', '96', '--file-name', probeEtl, '--file-size', '4'],
      { timeoutMs: 10_000 }
    )
    await run(this.toolPath, ['stop'], { timeoutMs: 8000 }).catch(() => undefined)

    if (probe.code !== 0 || /access is denied/i.test(probe.stderr + probe.stdout)) {
      this.cleanup()
      const denied = /access is denied/i.test(probe.stderr + probe.stdout)
      throw new Error(
        denied
          ? 'pktmon needs Administrator rights. Restart blazma.nt as Administrator to capture without Npcap.'
          : `pktmon could not start: ${(probe.stderr || probe.stdout).trim().slice(0, 200)}`
      )
    }

    this.stopped = false
    void this.loop(events)
  }

  private async loop(events: CaptureSourceEvents): Promise<void> {
    this.looping = true
    let cycle = 0

    while (!this.stopped) {
      const etl = join(this.workDir!, `c${cycle}.etl`)
      const pcap = join(this.workDir!, `c${cycle}.pcap`)

      try {
        const started = await run(
          this.toolPath,
          [
            'start',
            '--capture',
            '--pkt-size',
            String(this.snapLength),
            '--file-name',
            etl,
            // Large cap so a single short cycle never rotates into multiple files.
            '--file-size',
            '512'
          ],
          { timeoutMs: 10_000 }
        )
        if (started.code !== 0) {
          events.onError(`pktmon start failed: ${(started.stderr || started.stdout).trim().slice(0, 200)}`, true)
          break
        }

        await this.sleep(this.cycleMs)
        await run(this.toolPath, ['stop'], { timeoutMs: 8000 }).catch(() => undefined)

        const converted = await run(this.toolPath, ['etl2pcap', etl, '--out', pcap], { timeoutMs: 15_000 })
        if (converted.code === 0) this.feed(pcap, events)
      } catch (err) {
        events.onError(`pktmon cycle error: ${String(err)}`, false)
      } finally {
        rmSync(etl, { force: true })
        rmSync(pcap, { force: true })
        cycle++
      }
    }

    this.looping = false
  }

  /** Reads one converted pcap segment and emits its packets. */
  private feed(pcapPath: string, events: CaptureSourceEvents): void {
    let buffer: Buffer
    try {
      buffer = readFileSync(pcapPath)
    } catch {
      return
    }
    if (buffer.length < 24) return

    const reader = new PcapStreamReader()
    const packets = reader.push(new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength))
    for (const packet of packets) events.onPacket(packet, reader.linkType)
    if (reader.error) events.onError(`pktmon output could not be read: ${reader.error}`, false)
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const timer = setTimeout(resolve, ms)
      // Resolve early if stop() is called mid-cycle.
      this.wake = () => {
        clearTimeout(timer)
        resolve()
      }
    })
  }

  private wake: (() => void) | null = null

  async stop(): Promise<void> {
    this.stopped = true
    if (this.wake) this.wake()
    await run(this.toolPath, ['stop'], { timeoutMs: 8000 }).catch(() => undefined)
    // Give the loop a moment to exit its current cycle, then clean up.
    await this.sleep(200)
    this.cleanup()
  }

  private cleanup(): void {
    if (!this.workDir) return
    rmSync(this.workDir, { recursive: true, force: true })
    this.workDir = null
  }
}
