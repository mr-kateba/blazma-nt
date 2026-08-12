/**
 * Incremental libpcap ("classic" pcap) stream reader.
 *
 * dumpcap is asked to write pcap rather than pcapng (`-P`), so this parser only
 * has to handle the 24-byte file header plus 16-byte per-packet records. Data
 * arrives in arbitrary chunks from a pipe, so the reader buffers partial
 * records and emits packets as soon as they are complete.
 */

export interface PcapPacket {
  /** Milliseconds since epoch. */
  ts: number
  /** Length of the frame on the wire, which may exceed data.length. */
  wireLength: number
  data: Uint8Array
}

const MAGIC_LE = 0xd4c3b2a1
const MAGIC_BE = 0xa1b2c3d4
const MAGIC_NS_LE = 0x4d3cb2a1
const MAGIC_NS_BE = 0xa1b23c4d

const MAX_PACKET_BYTES = 262144

export class PcapStreamReader {
  private buffer: Uint8Array = new Uint8Array(0)
  private headerParsed = false
  private littleEndian = true
  private nanoseconds = false
  private linkTypeValue = 1
  private failed: string | null = null

  get linkType(): number {
    return this.linkTypeValue
  }

  get error(): string | null {
    return this.failed
  }

  /** Feeds a chunk and returns every packet that became complete. */
  push(chunk: Uint8Array): PcapPacket[] {
    if (this.failed) return []

    if (this.buffer.length === 0) {
      this.buffer = chunk
    } else {
      const merged = new Uint8Array(this.buffer.length + chunk.length)
      merged.set(this.buffer, 0)
      merged.set(chunk, this.buffer.length)
      this.buffer = merged
    }

    const out: PcapPacket[] = []

    if (!this.headerParsed) {
      if (this.buffer.length < 24) return out
      const view = new DataView(this.buffer.buffer, this.buffer.byteOffset, this.buffer.byteLength)
      const magicBe = view.getUint32(0, false)

      if (magicBe === MAGIC_BE) {
        this.littleEndian = false
      } else if (magicBe === MAGIC_LE) {
        this.littleEndian = true
      } else if (magicBe === MAGIC_NS_BE) {
        this.littleEndian = false
        this.nanoseconds = true
      } else if (magicBe === MAGIC_NS_LE) {
        this.littleEndian = true
        this.nanoseconds = true
      } else if (magicBe === 0x0a0d0d0a) {
        this.failed = 'Capture tool produced pcapng; this reader expects classic pcap (dumpcap -P).'
        return out
      } else {
        this.failed = `Unrecognised pcap magic 0x${magicBe.toString(16)}.`
        return out
      }

      this.linkTypeValue = view.getUint32(20, this.littleEndian)
      this.buffer = this.buffer.subarray(24)
      this.headerParsed = true
    }

    let offset = 0
    while (this.buffer.length - offset >= 16) {
      const view = new DataView(this.buffer.buffer, this.buffer.byteOffset + offset, 16)
      const tsSec = view.getUint32(0, this.littleEndian)
      const tsFrac = view.getUint32(4, this.littleEndian)
      const capturedLength = view.getUint32(8, this.littleEndian)
      const wireLength = view.getUint32(12, this.littleEndian)

      if (capturedLength > MAX_PACKET_BYTES) {
        this.failed = `Implausible packet length ${capturedLength}; stopping to avoid unbounded buffering.`
        this.buffer = new Uint8Array(0)
        return out
      }
      if (this.buffer.length - offset - 16 < capturedLength) break

      const start = offset + 16
      out.push({
        ts: tsSec * 1000 + (this.nanoseconds ? tsFrac / 1e6 : tsFrac / 1000),
        wireLength: wireLength || capturedLength,
        data: this.buffer.subarray(start, start + capturedLength)
      })
      offset = start + capturedLength
    }

    // Copy the tail so the retained slice does not pin the whole chunk.
    this.buffer = offset === 0 ? this.buffer : Uint8Array.prototype.slice.call(this.buffer, offset)
    return out
  }
}
