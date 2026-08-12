import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import type { CaptureBackendId } from '../../shared/types.js'
import { validateBpfFilter, validateInterfaceId } from '../security/validate.js'
import { PcapStreamReader } from './pcapStream.js'
import type { CaptureSource, CaptureSourceEvents } from './source.js'

export interface DumpcapOptions {
  toolPath: string
  interfaceId: string
  /** Bytes captured per frame. Enough for DNS, TLS SNI and HTTP request lines. */
  snapLength?: number
  filter?: string
  /** Version banner from `dumpcap --version`, used to pick the format flag. */
  version?: string | null
}

/**
 * Selects the arguments that make dumpcap emit classic pcap rather than pcapng.
 *
 * Wireshark 4.2 introduced `-F <type>` and deprecated `-P`; older builds only
 * understand `-P`. Reading the version banner keeps both working and stops the
 * deprecation warning on current releases.
 */
export function pcapFormatArgs(version: string | null | undefined): string[] {
  const match = version?.match(/(\d+)\.(\d+)/)
  if (!match) return ['-P']
  const major = Number(match[1])
  const minor = Number(match[2])
  return major > 4 || (major === 4 && minor >= 2) ? ['-F', 'pcap'] : ['-P']
}

/**
 * Live capture through dumpcap (the capture-only helper shipped with Wireshark,
 * backed by Npcap). dumpcap is used rather than tshark because it does no
 * dissection of its own: it hands us raw frames, and all analysis happens in
 * this application where we control exactly what is read.
 *
 * `-P` selects classic pcap output, `-w -` streams to stdout, and `-q`
 * suppresses the interactive packet counter.
 */
export class DumpcapSource implements CaptureSource {
  readonly id: CaptureBackendId = 'npcap-dumpcap'

  private child: ChildProcessWithoutNullStreams | null = null
  private reader = new PcapStreamReader()
  private stopped = false
  private stderrTail = ''

  constructor(private readonly options: DumpcapOptions) {}

  get running(): boolean {
    return this.child !== null && !this.stopped
  }

  async start(events: CaptureSourceEvents): Promise<void> {
    const interfaceId = validateInterfaceId(this.options.interfaceId)
    if (interfaceId.startsWith('alias:')) {
      throw new Error('This adapter has no Npcap capture device. Install Npcap or choose another interface.')
    }
    const filter = validateBpfFilter(this.options.filter ?? '')
    const snapLength = Math.min(Math.max(this.options.snapLength ?? 1024, 96), 65535)

    const args = [
      '-i',
      interfaceId,
      ...pcapFormatArgs(this.options.version),
      '-w',
      '-',
      '-q',
      '-s',
      String(snapLength),
      '-B',
      '16'
    ]
    if (filter) args.push('-f', filter)

    this.stopped = false
    this.reader = new PcapStreamReader()

    const child = spawn(this.options.toolPath, args, { windowsHide: true, shell: false })
    this.child = child

    child.stdout.on('data', (chunk: Buffer) => {
      const packets = this.reader.push(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength))
      const linkType = this.reader.linkType
      for (const packet of packets) events.onPacket(packet, linkType)
      if (this.reader.error) {
        events.onError(this.reader.error, true)
        void this.stop()
      }
    })

    child.stderr.on('data', (chunk: Buffer) => {
      const text = chunk.toString('utf8')
      this.stderrTail = (this.stderrTail + text).slice(-2000)
      const dropped = text.match(/(\d+)\s+packets? dropped/i)
      if (dropped && events.onStats) events.onStats({ dropped: Number(dropped[1]) })
    })

    child.on('error', (err) => {
      events.onError(`Failed to run dumpcap: ${err.message}`, true)
    })

    child.on('close', (code) => {
      this.child = null
      if (this.stopped) return
      const detail = this.stderrTail.trim().split('\n').slice(-3).join(' ').slice(0, 400)
      events.onError(
        code === 0
          ? 'Capture ended unexpectedly.'
          : `dumpcap exited with code ${code}. ${detail || 'Check that the interface is up and that you have capture permission.'}`,
        true
      )
    })

    // Surface an immediate startup failure (bad interface, missing Npcap driver)
    // instead of reporting "running" for a process that already died.
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(resolve, 700)
      child.once('close', (code) => {
        clearTimeout(timer)
        if (code !== 0) {
          const detail = this.stderrTail.trim().split('\n').slice(-3).join(' ').slice(0, 400)
          reject(new Error(detail || `dumpcap exited immediately with code ${code}.`))
        } else {
          resolve()
        }
      })
    })
  }

  async stop(): Promise<void> {
    this.stopped = true
    const child = this.child
    if (!child) return
    this.child = null
    child.kill()
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        child.kill('SIGKILL')
        resolve()
      }, 2000)
      child.once('close', () => {
        clearTimeout(timer)
        resolve()
      })
    })
  }
}
