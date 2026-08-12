import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { statSync } from 'node:fs'
import type { PcapJobOptions, PcapJobStatus } from '../../shared/types.js'
import { validateBpfFilter, validateInt, validateInterfaceId, validateSavePath } from '../security/validate.js'
import { pcapFormatArgs } from './dumpcapSource.js'
import type { EventBus } from '../core/bus.js'
import type { Logger } from '../utils/logger.js'

const SCOPE = 'pcap'

/**
 * Explicit, user-initiated packet capture to a file.
 *
 * Nothing here runs unless the user starts it and names an output file: there
 * is no automatic or background PCAP writing anywhere in the application. Both
 * a duration and a size limit are enforced by dumpcap itself (-a), so a
 * forgotten capture cannot fill the disk.
 */
export class PcapJob {
  private child: ChildProcessWithoutNullStreams | null = null
  private status: PcapJobStatus = {
    running: false,
    outputPath: null,
    startedAt: null,
    bytesWritten: 0,
    secondsElapsed: 0,
    error: null
  }
  private ticker: NodeJS.Timeout | null = null

  constructor(
    private readonly bus: EventBus,
    private readonly log: Logger
  ) {}

  getStatus(): PcapJobStatus {
    return { ...this.status }
  }

  private emit(): void {
    this.bus.emit('pcap:status', this.getStatus())
  }

  start(options: PcapJobOptions, toolPath: string, toolVersion: string | null = null): PcapJobStatus {
    if (this.status.running) throw new Error('A packet capture is already running.')

    const interfaceId = validateInterfaceId(options.interfaceId)
    if (interfaceId.startsWith('alias:')) {
      throw new Error('This adapter has no Npcap capture device, so it cannot be recorded.')
    }
    const filter = validateBpfFilter(options.filter)
    const seconds = validateInt(options.maxSeconds, 1, 24 * 60 * 60, 'Capture duration')
    const megabytes = validateInt(options.maxMegabytes, 1, 10_240, 'Maximum file size')
    const outputPath = validateSavePath(options.outputPath, ['.pcap', '.pcapng'])

    const args = [
      '-i',
      interfaceId,
      '-w',
      outputPath,
      '-a',
      `duration:${seconds}`,
      '-a',
      `filesize:${megabytes * 1024}`,
      '-q'
    ]
    // dumpcap defaults to pcapng. Honour the extension the user chose so a file
    // named .pcap really is classic pcap.
    if (outputPath.toLowerCase().endsWith('.pcap')) args.push(...pcapFormatArgs(toolVersion))
    if (filter) args.push('-f', filter)

    const child = spawn(toolPath, args, { windowsHide: true, shell: false })
    this.child = child
    this.status = {
      running: true,
      outputPath,
      startedAt: Date.now(),
      bytesWritten: 0,
      secondsElapsed: 0,
      error: null
    }
    this.log.info(SCOPE, `Packet capture started -> ${outputPath} (max ${seconds}s / ${megabytes} MB)`)

    let stderrTail = ''
    child.stderr.on('data', (chunk: Buffer) => {
      stderrTail = (stderrTail + chunk.toString('utf8')).slice(-1000)
    })

    child.on('error', (err) => {
      this.status.error = `Failed to run dumpcap: ${err.message}`
      this.finish()
    })

    child.on('close', (code) => {
      if (code !== 0 && !this.status.error) {
        this.status.error = `dumpcap exited with code ${code}. ${stderrTail.trim().slice(-300)}`
      }
      this.finish()
    })

    this.ticker = setInterval(() => {
      if (!this.status.startedAt) return
      this.status.secondsElapsed = Math.round((Date.now() - this.status.startedAt) / 1000)
      try {
        this.status.bytesWritten = statSync(outputPath).size
      } catch {
        // The file appears a moment after dumpcap starts; not an error.
      }
      this.emit()
    }, 1000)

    this.emit()
    return this.getStatus()
  }

  stop(): PcapJobStatus {
    const child = this.child
    if (child) {
      this.child = null
      child.kill()
    }
    this.finish()
    return this.getStatus()
  }

  private finish(): void {
    if (this.ticker) {
      clearInterval(this.ticker)
      this.ticker = null
    }
    if (this.status.outputPath) {
      try {
        this.status.bytesWritten = statSync(this.status.outputPath).size
      } catch {
        // File may not exist if dumpcap failed before writing.
      }
    }
    if (this.status.running) {
      this.log.info(
        SCOPE,
        `Packet capture finished (${this.status.bytesWritten} bytes)${this.status.error ? `: ${this.status.error}` : ''}`
      )
    }
    this.status.running = false
    this.child = null
    this.emit()
  }
}
