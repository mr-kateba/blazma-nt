import type { AnalyticsReport, TimeRange } from '../../shared/types.js'
import type { Store } from '../database/store.js'
import { resolveRange } from './ranges.js'

/**
 * Builds an analytics report entirely from stored aggregates. Every number is
 * derived from measured traffic; nothing is estimated or back-filled.
 */
export function buildReport(store: Store, range: TimeRange, now = Date.now()): AnalyticsReport {
  const { from, to, bucketMs } = resolveRange(range, now)
  const series = store.trafficSeries(from, to, bucketMs)

  let bytesUp = 0
  let bytesDown = 0
  let packets = 0
  let peakBytesPerBucket = 0
  let peakAt: number | null = null

  for (const sample of series) {
    bytesUp += sample.bytesUp
    bytesDown += sample.bytesDown
    packets += sample.packets
    const bucketBytes = sample.bytesUp + sample.bytesDown
    if (bucketBytes > peakBytesPerBucket) {
      peakBytesPerBucket = bucketBytes
      peakAt = sample.ts
    }
  }

  const totalBytes = bytesUp + bytesDown
  const windowSeconds = Math.max((to - from) / 1000, 1)
  const bucketSeconds = Math.max(bucketMs / 1000, 1)

  const talkers = store.topTalkers(from, 1)
  const destinations = store.topDestinations(from, 1)
  const protocols = store.topProtocols(from, 1)
  const connections = store.queryFlows({ from, to, limit: 1 }).total

  return {
    range,
    from,
    to,
    avgBandwidthBps: (totalBytes * 8) / windowSeconds,
    peakBandwidthBps: (peakBytesPerBucket * 8) / bucketSeconds,
    peakAt,
    avgPacketsPerSec: packets / windowSeconds,
    totalBytes,
    bytesUp,
    bytesDown,
    // Guarded so the UI never has to render Infinity when nothing came down.
    upDownRatio: bytesDown > 0 ? bytesUp / bytesDown : 0,
    connectionCount: connections,
    topDevice: talkers[0] ? { label: talkers[0].label, bytes: talkers[0].bytes } : null,
    topDestination: destinations[0] ? { label: destinations[0].label, bytes: destinations[0].bytes } : null,
    topProtocol: protocols[0] ?? null,
    series
  }
}
