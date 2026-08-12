import type { Direction, EncryptionStatus, FlowState, TransportProtocol } from '../../shared/types.js'
import type { ParsedPacket } from '../parser/types.js'
import { flowKey } from '../utils/net.js'

export interface TrackedFlow {
  key: string
  srcIp: string
  srcPort: number
  dstIp: string
  dstPort: number
  transport: TransportProtocol
  appProtocol: string
  confidence: ParsedPacket['confidence']
  encryption: EncryptionStatus
  direction: Direction
  state: FlowState
  firstSeen: number
  lastSeen: number
  bytesUp: number
  bytesDown: number
  packetsUp: number
  packetsDown: number
  serverName: string | null
  remoteHostname: string | null
  deviceMac: string | null
  deviceIp: string | null
  /** Bytes/packets since the last UI tick; reset by drainDeltas(). */
  deltaBytes: number
  deltaPackets: number
  /** Set once the flow has been reported as closed, so it is emitted only once. */
  reported: boolean
}

export interface FlowUpdateInput {
  packet: ParsedPacket
  /** True when the source address belongs to the monitored local network. */
  srcIsLocal: boolean
  dstIsLocal: boolean
  deviceMac: string | null
  deviceIp: string | null
  serverName?: string | null
}

const IDLE_TIMEOUT_MS = 120_000
const CLOSED_GRACE_MS = 30_000
const TIME_WAIT_MS = 60_000

/**
 * Bidirectional flow table.
 *
 * Both directions of a conversation collapse onto one deterministic key, and
 * TCP state is derived from observed flags rather than assumed. The table is
 * bounded: once `maxFlows` is reached the least recently seen entries are
 * evicted, so a scan or a flood cannot grow memory without limit.
 */
export class FlowTracker {
  private flows = new Map<string, TrackedFlow>()

  constructor(private readonly maxFlows = 20_000) {}

  get size(): number {
    return this.flows.size
  }

  values(): IterableIterator<TrackedFlow> {
    return this.flows.values()
  }

  get(key: string): TrackedFlow | undefined {
    return this.flows.get(key)
  }

  update(input: FlowUpdateInput): TrackedFlow {
    const { packet, srcIsLocal, dstIsLocal } = input
    const srcIp = packet.srcIp ?? '0.0.0.0'
    const dstIp = packet.dstIp ?? '0.0.0.0'
    const { key } = flowKey(srcIp, packet.srcPort, dstIp, packet.dstPort, packet.transport)

    let flow = this.flows.get(key)
    const bytes = packet.wireLength

    if (!flow) {
      // Orient the record so src is the local side whenever one side is local.
      const localFirst = srcIsLocal || !dstIsLocal
      flow = {
        key,
        srcIp: localFirst ? srcIp : dstIp,
        srcPort: localFirst ? packet.srcPort : packet.dstPort,
        dstIp: localFirst ? dstIp : srcIp,
        dstPort: localFirst ? packet.dstPort : packet.srcPort,
        transport: packet.transport,
        appProtocol: packet.appProtocol,
        confidence: packet.confidence,
        encryption: encryptionOf(packet),
        direction: directionOf(srcIsLocal, dstIsLocal),
        state: packet.transport === 'TCP' ? 'NEW' : 'ESTABLISHED',
        firstSeen: packet.ts,
        lastSeen: packet.ts,
        bytesUp: 0,
        bytesDown: 0,
        packetsUp: 0,
        packetsDown: 0,
        serverName: input.serverName ?? null,
        remoteHostname: null,
        deviceMac: input.deviceMac,
        deviceIp: input.deviceIp,
        deltaBytes: 0,
        deltaPackets: 0,
        reported: false
      }
      this.flows.set(key, flow)
      this.evictIfNeeded()
    }

    // The flow is oriented with the local device as `src`, so a packet sent by
    // that side counts as upload and everything else as download.
    const fromFlowSource = srcIp === flow.srcIp && packet.srcPort === flow.srcPort

    if (fromFlowSource) {
      flow.bytesUp += bytes
      flow.packetsUp += 1
    } else {
      flow.bytesDown += bytes
      flow.packetsDown += 1
    }
    flow.deltaBytes += bytes
    flow.deltaPackets += 1
    flow.lastSeen = packet.ts

    // Header-derived labels always win over an earlier port hint.
    if (packet.confidence === 'header' && flow.confidence !== 'header') {
      flow.appProtocol = packet.appProtocol
      flow.confidence = packet.confidence
      flow.encryption = encryptionOf(packet)
    } else if (packet.confidence === 'header') {
      const next = encryptionOf(packet)
      if (next !== 'unknown') flow.encryption = next
      if (packet.appProtocol !== flow.transport) flow.appProtocol = packet.appProtocol
    }

    if (input.serverName && !flow.serverName) flow.serverName = input.serverName
    if (!flow.deviceMac && input.deviceMac) flow.deviceMac = input.deviceMac
    if (!flow.deviceIp && input.deviceIp) flow.deviceIp = input.deviceIp

    if (packet.transport === 'TCP' && packet.tcpFlags) {
      flow.state = nextTcpState(flow.state, packet.tcpFlags)
    }

    return flow
  }

  /** Marks idle/closed flows and returns the keys removed from the table. */
  expire(now: number): string[] {
    const removed: string[] = []
    for (const [key, flow] of this.flows) {
      const idle = now - flow.lastSeen
      if (flow.state === 'CLOSED' && idle > CLOSED_GRACE_MS) {
        this.flows.delete(key)
        removed.push(key)
        continue
      }
      if (flow.state === 'TIME_WAIT' && idle > TIME_WAIT_MS) {
        this.flows.delete(key)
        removed.push(key)
        continue
      }
      if (idle > IDLE_TIMEOUT_MS) {
        this.flows.delete(key)
        removed.push(key)
      }
    }
    return removed
  }

  /** Returns flows with traffic since the last call and clears their deltas. */
  drainDeltas(): TrackedFlow[] {
    const changed: TrackedFlow[] = []
    for (const flow of this.flows.values()) {
      if (flow.deltaPackets === 0) continue
      changed.push({ ...flow })
      flow.deltaBytes = 0
      flow.deltaPackets = 0
    }
    return changed
  }

  private evictIfNeeded(): void {
    if (this.flows.size <= this.maxFlows) return
    const excess = this.flows.size - this.maxFlows
    const oldest = [...this.flows.values()].sort((a, b) => a.lastSeen - b.lastSeen).slice(0, excess)
    for (const flow of oldest) this.flows.delete(flow.key)
  }
}

export function encryptionOf(packet: ParsedPacket): EncryptionStatus {
  if (packet.encrypted === true) return 'encrypted'
  if (packet.encrypted === false) return 'unencrypted'
  return 'unknown'
}

export function directionOf(srcIsLocal: boolean, dstIsLocal: boolean): Direction {
  if (srcIsLocal && dstIsLocal) return 'local'
  if (srcIsLocal) return 'up'
  if (dstIsLocal) return 'down'
  return 'unknown'
}

/** TCP state machine driven purely by observed flags. */
export function nextTcpState(current: FlowState, flags: { syn: boolean; ack: boolean; fin: boolean; rst: boolean }): FlowState {
  if (flags.rst) return 'CLOSED'
  if (current === 'CLOSED') return 'CLOSED'
  if (flags.fin) return current === 'CLOSING' ? 'TIME_WAIT' : 'CLOSING'
  if (current === 'CLOSING' || current === 'TIME_WAIT') return current
  if (flags.syn && flags.ack) return 'ESTABLISHED'
  if (flags.syn) return 'NEW'
  if (flags.ack && current === 'NEW') return 'ESTABLISHED'
  return current
}
