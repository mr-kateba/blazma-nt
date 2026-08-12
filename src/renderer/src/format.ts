import type { Language } from '@shared/types'

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

export function formatBytes(bytes: number, digits = 2): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const exp = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), UNITS.length - 1)
  return `${(bytes / Math.pow(1024, exp)).toFixed(exp === 0 ? 0 : digits)} ${UNITS[exp]}`
}

export function formatRate(bytesPerSecond: number): string {
  return `${formatBytes(bytesPerSecond, 1)}/s`
}

export function formatBits(bitsPerSecond: number): string {
  if (!Number.isFinite(bitsPerSecond) || bitsPerSecond <= 0) return '0 bps'
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps']
  const exp = Math.min(Math.floor(Math.log(bitsPerSecond) / Math.log(1000)), units.length - 1)
  return `${(bitsPerSecond / Math.pow(1000, exp)).toFixed(exp === 0 ? 0 : 1)} ${units[exp]}`
}

export function formatNumber(value: number, language: Language = 'en'): string {
  if (!Number.isFinite(value)) return '—'
  // Latin digits everywhere: mixing Arabic-Indic digits into IPs and ports
  // makes network data much harder to read.
  return new Intl.NumberFormat(language === 'ar' ? 'ar-EG-u-nu-latn' : 'en-US').format(Math.round(value))
}

export function formatTime(ts: number): string {
  if (!ts) return '—'
  const date = new Date(ts)
  return date.toLocaleTimeString('en-GB', { hour12: false })
}

export function formatDateTime(ts: number): string {
  if (!ts) return '—'
  const date = new Date(ts)
  return `${date.toLocaleDateString('en-GB')} ${date.toLocaleTimeString('en-GB', { hour12: false })}`
}

export function formatRelative(ts: number, language: Language): string {
  if (!ts) return '—'
  const seconds = Math.round((Date.now() - ts) / 1000)
  const ar = language === 'ar'
  if (seconds < 5) return ar ? 'الآن' : 'now'
  if (seconds < 60) return ar ? `قبل ${seconds} ث` : `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return ar ? `قبل ${minutes} د` : `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return ar ? `قبل ${hours} س` : `${hours}h ago`
  return ar ? `قبل ${Math.floor(hours / 24)} ي` : `${Math.floor(hours / 24)}d ago`
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
