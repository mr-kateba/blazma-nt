import type { AlertKind, AlertRecord, AlertSeverity } from '../../shared/types.js'
import { formatBytes } from '../utils/bytes.js'

export type NewAlert = Omit<AlertRecord, 'id'>

export interface AlertThresholds {
  /** Distinct destination ports from one source within the window. */
  portScanPorts: number
  portScanWindowMs: number
  /** DNS queries from one device within the window. */
  dnsBurstQueries: number
  dnsBurstWindowMs: number
  /** Multiple of the rolling average that counts as a spike. */
  spikeMultiplier: number
  /** Bytes per second sustained over a tick that counts as high bandwidth. */
  highBandwidthBps: number
  /** Upload bytes from one device within the window. */
  largeUploadBytes: number
  largeUploadWindowMs: number
}

export const DEFAULT_THRESHOLDS: AlertThresholds = {
  portScanPorts: 25,
  portScanWindowMs: 20_000,
  dnsBurstQueries: 150,
  dnsBurstWindowMs: 60_000,
  spikeMultiplier: 6,
  highBandwidthBps: 25 * 1024 * 1024,
  largeUploadBytes: 500 * 1024 * 1024,
  largeUploadWindowMs: 10 * 60_000
}

interface Window {
  start: number
  values: Set<number>
}

/**
 * Observational alerting.
 *
 * Every rule states what was measured and against which threshold. Nothing here
 * concludes that traffic is malicious — a port-scan *pattern* is reported as a
 * pattern, because the same shape is produced by legitimate scanners, service
 * discovery and network tools.
 */
export class AlertEngine {
  private portWindows = new Map<string, Window>()
  private dnsWindows = new Map<string, { start: number; count: number }>()
  private uploadWindows = new Map<string, { start: number; bytes: number }>()
  private lastFired = new Map<string, number>()
  private bandwidthHistory: number[] = []
  private protocolSeen = new Set<string>()

  constructor(private readonly thresholds: AlertThresholds = DEFAULT_THRESHOLDS) {}

  /** Suppresses repeats of the same alert key inside `cooldownMs`. */
  private allow(key: string, now: number, cooldownMs: number): boolean {
    const last = this.lastFired.get(key)
    if (last !== undefined && now - last < cooldownMs) return false
    this.lastFired.set(key, now)
    return true
  }

  newDevice(device: { mac: string | null; ipv4: string | null; vendor: string | null }, now: number): NewAlert | null {
    const id = device.mac ?? device.ipv4 ?? 'unknown'
    if (!this.allow(`new-device:${id}`, now, 60 * 60_000)) return null
    return {
      ts: now,
      kind: 'new-device',
      severity: 'INFO',
      title: 'New device detected',
      reason:
        `A device not seen before in this session appeared on the network` +
        (device.vendor ? ` (vendor: ${device.vendor})` : '') +
        '. This is expected when a phone, laptop or IoT device joins.',
      deviceIp: device.ipv4,
      deviceMac: device.mac,
      acknowledged: false,
      details: JSON.stringify({ mac: device.mac, ip: device.ipv4, vendor: device.vendor })
    }
  }

  unencryptedProtocol(
    info: { protocol: string; deviceIp: string | null; deviceMac: string | null; dstIp: string; dstPort: number },
    now: number
  ): NewAlert | null {
    const key = `unenc:${info.deviceIp}:${info.protocol}:${info.dstPort}`
    if (!this.allow(key, now, 10 * 60_000)) return null
    const severity: AlertSeverity = info.protocol === 'TELNET' || info.protocol === 'FTP' ? 'MEDIUM' : 'LOW'
    return {
      ts: now,
      kind: 'unencrypted-protocol',
      severity,
      title: `Unencrypted ${info.protocol} traffic`,
      reason:
        `${info.protocol} sends its data in the clear, so anyone able to observe this network segment can read it. ` +
        `Observed towards ${info.dstIp}:${info.dstPort}. Consider the encrypted equivalent where one exists.`,
      deviceIp: info.deviceIp,
      deviceMac: info.deviceMac,
      acknowledged: false,
      details: JSON.stringify(info)
    }
  }

  /** Tracks distinct destination ports per source to spot scan-shaped traffic. */
  observeConnection(srcIp: string, dstPort: number, now: number): NewAlert | null {
    let window = this.portWindows.get(srcIp)
    if (!window || now - window.start > this.thresholds.portScanWindowMs) {
      window = { start: now, values: new Set() }
      this.portWindows.set(srcIp, window)
    }
    window.values.add(dstPort)
    if (window.values.size < this.thresholds.portScanPorts) return null
    if (!this.allow(`scan:${srcIp}`, now, 10 * 60_000)) return null

    const count = window.values.size
    window.values.clear()
    window.start = now
    return {
      ts: now,
      kind: 'port-scan-pattern',
      severity: 'MEDIUM',
      title: 'Port-scan pattern observed',
      reason:
        `${srcIp} contacted ${count} distinct destination ports within ` +
        `${Math.round(this.thresholds.portScanWindowMs / 1000)} seconds. Network scanners, security tools and some ` +
        `peer-to-peer applications all produce this pattern — it is a shape, not a verdict.`,
      deviceIp: srcIp,
      deviceMac: null,
      acknowledged: false,
      details: JSON.stringify({ srcIp, distinctPorts: count })
    }
  }

  observeDnsQuery(deviceIp: string | null, now: number): NewAlert | null {
    if (!deviceIp) return null
    let window = this.dnsWindows.get(deviceIp)
    if (!window || now - window.start > this.thresholds.dnsBurstWindowMs) {
      window = { start: now, count: 0 }
      this.dnsWindows.set(deviceIp, window)
    }
    window.count += 1
    if (window.count < this.thresholds.dnsBurstQueries) return null
    if (!this.allow(`dns:${deviceIp}`, now, 15 * 60_000)) return null

    const count = window.count
    window.count = 0
    window.start = now
    return {
      ts: now,
      kind: 'excessive-dns',
      severity: 'LOW',
      title: 'High DNS query rate',
      reason:
        `${deviceIp} made ${count} DNS queries in ${Math.round(this.thresholds.dnsBurstWindowMs / 1000)} seconds. ` +
        `Ad-heavy browsing, sync clients and misconfigured software commonly cause this.`,
      deviceIp,
      deviceMac: null,
      acknowledged: false,
      details: JSON.stringify({ deviceIp, queries: count })
    }
  }

  observeUpload(deviceIp: string | null, deviceMac: string | null, bytes: number, now: number): NewAlert | null {
    if (!deviceIp || bytes <= 0) return null
    let window = this.uploadWindows.get(deviceIp)
    if (!window || now - window.start > this.thresholds.largeUploadWindowMs) {
      window = { start: now, bytes: 0 }
      this.uploadWindows.set(deviceIp, window)
    }
    window.bytes += bytes
    if (window.bytes < this.thresholds.largeUploadBytes) return null
    if (!this.allow(`upload:${deviceIp}`, now, 30 * 60_000)) return null

    const total = window.bytes
    window.bytes = 0
    window.start = now
    return {
      ts: now,
      kind: 'large-upload',
      severity: 'MEDIUM',
      title: 'Large sustained upload',
      reason:
        `${deviceIp} uploaded ${formatBytes(total)} in the last ` +
        `${Math.round(this.thresholds.largeUploadWindowMs / 60000)} minutes. Cloud backup, video calls and file ` +
        `sharing all look like this; check whether it matches what the device should be doing.`,
      deviceIp,
      deviceMac,
      acknowledged: false,
      details: JSON.stringify({ deviceIp, bytes: total })
    }
  }

  /** Called once per statistics tick with the measured throughput. */
  observeBandwidth(bytesPerSecond: number, now: number): NewAlert[] {
    const out: NewAlert[] = []

    if (bytesPerSecond > this.thresholds.highBandwidthBps && this.allow('high-bandwidth', now, 10 * 60_000)) {
      out.push({
        ts: now,
        kind: 'high-bandwidth',
        severity: 'LOW',
        title: 'Very high bandwidth usage',
        reason:
          `Total throughput reached ${formatBytes(bytesPerSecond)}/s, above the configured threshold of ` +
          `${formatBytes(this.thresholds.highBandwidthBps)}/s.`,
        deviceIp: null,
        deviceMac: null,
        acknowledged: false,
        details: JSON.stringify({ bytesPerSecond })
      })
    }

    // Rolling baseline over the last two minutes of ticks.
    this.bandwidthHistory.push(bytesPerSecond)
    if (this.bandwidthHistory.length > 120) this.bandwidthHistory.shift()

    if (this.bandwidthHistory.length >= 30) {
      const previous = this.bandwidthHistory.slice(0, -1)
      const average = previous.reduce((a, b) => a + b, 0) / previous.length
      if (
        average > 8 * 1024 &&
        bytesPerSecond > average * this.thresholds.spikeMultiplier &&
        this.allow('spike', now, 5 * 60_000)
      ) {
        out.push({
          ts: now,
          kind: 'traffic-spike',
          severity: 'LOW',
          title: 'Abnormal traffic spike',
          reason:
            `Throughput jumped to ${formatBytes(bytesPerSecond)}/s, about ` +
            `${Math.round(bytesPerSecond / average)}x the recent average of ${formatBytes(average)}/s.`,
          deviceIp: null,
          deviceMac: null,
          acknowledged: false,
          details: JSON.stringify({ bytesPerSecond, average })
        })
      }
    }

    return out
  }

  /** Fires once per protocol label we cannot identify from headers or ports. */
  observeUnknownProtocol(transport: string, port: number, now: number): NewAlert | null {
    const key = `${transport}:${port}`
    if (this.protocolSeen.has(key)) return null
    this.protocolSeen.add(key)
    if (this.protocolSeen.size > 4096) this.protocolSeen.clear()
    if (!this.allow(`unknown:${key}`, now, 60 * 60_000)) return null
    return {
      ts: now,
      kind: 'unknown-protocol',
      severity: 'INFO',
      title: 'Unrecognised protocol',
      reason:
        `Traffic on ${transport} port ${port} did not match any protocol this tool can identify from packet ` +
        `headers. Unusual ports are common for games, custom services and proprietary applications.`,
      deviceIp: null,
      deviceMac: null,
      acknowledged: false,
      details: JSON.stringify({ transport, port })
    }
  }
}

export const ALERT_KINDS: AlertKind[] = [
  'new-device',
  'unencrypted-protocol',
  'traffic-spike',
  'high-bandwidth',
  'port-scan-pattern',
  'excessive-dns',
  'large-upload',
  'unknown-protocol'
]
