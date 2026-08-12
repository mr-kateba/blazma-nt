/** Formatting and unit helpers shared by backend reports and exports. */

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'] as const

export function formatBytes(bytes: number, digits = 2): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const exp = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), UNITS.length - 1)
  const value = bytes / Math.pow(1024, exp)
  return `${value.toFixed(exp === 0 ? 0 : digits)} ${UNITS[exp]}`
}

export function formatBitrate(bitsPerSecond: number): string {
  if (!Number.isFinite(bitsPerSecond) || bitsPerSecond <= 0) return '0 bps'
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps']
  const exp = Math.min(Math.floor(Math.log(bitsPerSecond) / Math.log(1000)), units.length - 1)
  return `${(bitsPerSecond / Math.pow(1000, exp)).toFixed(exp === 0 ? 0 : 2)} ${units[exp]}`
}

export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '—'
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ${s % 60}s`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ${m % 60}m`
  return `${Math.floor(h / 24)}d ${h % 24}h`
}
