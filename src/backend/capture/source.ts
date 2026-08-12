import type { CaptureBackendId } from '../../shared/types.js'
import type { PcapPacket } from './pcapStream.js'

export interface CaptureSourceEvents {
  onPacket: (packet: PcapPacket, linkType: number) => void
  onError: (message: string, fatal: boolean) => void
  onStats?: (stats: { dropped: number }) => void
}

/**
 * A capture source produces frames from one adapter. Implementations must not
 * transmit anything on the network: every backend here is strictly read-only,
 * which is what keeps the tool from disturbing the network it observes.
 */
export interface CaptureSource {
  readonly id: CaptureBackendId
  start(events: CaptureSourceEvents): Promise<void>
  stop(): Promise<void>
  readonly running: boolean
}
