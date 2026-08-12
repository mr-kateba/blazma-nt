import type { TimeRange } from '../../shared/types.js'

/**
 * Time ranges and their chart bucket size. Buckets keep the number of points
 * sent to the UI roughly constant (60–180) no matter how long the range is.
 */
const RANGES: Record<TimeRange, { windowMs: number; bucketMs: number }> = {
  '1m': { windowMs: 60_000, bucketMs: 1_000 },
  '5m': { windowMs: 5 * 60_000, bucketMs: 5_000 },
  '15m': { windowMs: 15 * 60_000, bucketMs: 10_000 },
  '1h': { windowMs: 60 * 60_000, bucketMs: 30_000 },
  '24h': { windowMs: 24 * 60 * 60_000, bucketMs: 10 * 60_000 },
  '7d': { windowMs: 7 * 24 * 60 * 60_000, bucketMs: 60 * 60_000 },
  '30d': { windowMs: 30 * 24 * 60 * 60_000, bucketMs: 6 * 60 * 60_000 }
}

export function isTimeRange(value: unknown): value is TimeRange {
  return typeof value === 'string' && value in RANGES
}

export function resolveRange(range: TimeRange, now = Date.now()): { from: number; to: number; bucketMs: number } {
  const spec = RANGES[range] ?? RANGES['15m']
  return { from: now - spec.windowMs, to: now, bucketMs: spec.bucketMs }
}
