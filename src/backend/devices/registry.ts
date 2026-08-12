import { isMulticastOrBroadcast, isPrivateIp } from '../utils/net.js'
import { lookupVendor } from './vendors.js'

export interface TrackedDevice {
  mac: string | null
  ipv4: string | null
  ipv6: string | null
  hostname: string | null
  vendor: string | null
  firstSeen: number
  lastSeen: number
  bytesUp: number
  bytesDown: number
  packetsUp: number
  packetsDown: number
  isLocal: boolean
  /** Bytes since the last flush, used for per-device time series. */
  deltaUp: number
  deltaDown: number
  deltaPackets: number
  /** True until the device has been announced as new. */
  fresh: boolean
}

/**
 * In-memory device table keyed by MAC, since a device keeps its MAC across DHCP
 * leases. Devices seen only by IP (routed traffic, or the system-only backend)
 * are keyed by IP instead.
 */
export class DeviceRegistry {
  private byKey = new Map<string, TrackedDevice>()
  private ipIndex = new Map<string, string>()

  constructor(private readonly maxDevices = 4096) {}

  get size(): number {
    return this.byKey.size
  }

  values(): IterableIterator<TrackedDevice> {
    return this.byKey.values()
  }

  findByIp(ip: string): TrackedDevice | undefined {
    const key = this.ipIndex.get(ip)
    return key ? this.byKey.get(key) : undefined
  }

  /**
   * Records an observation. Only addresses that belong to the monitored subnet
   * (or a private range) become devices; public addresses are remote endpoints
   * and are tracked as flow destinations, not as devices.
   */
  observe(input: {
    mac: string | null
    ip: string | null
    ts: number
    isLocal: boolean
    hostname?: string | null
  }): TrackedDevice | null {
    const { mac, ip, ts } = input
    if (!mac && !ip) return null
    if (ip && isMulticastOrBroadcast(ip)) return null
    if (!input.isLocal && !(ip && isPrivateIp(ip))) return null

    const key = mac ?? `ip:${ip}`
    let device = this.byKey.get(key)

    if (!device && ip) {
      // Same host may first appear by IP and later by MAC; merge on the IP index.
      const existingKey = this.ipIndex.get(ip)
      if (existingKey && existingKey !== key) {
        const existing = this.byKey.get(existingKey)
        if (existing && existingKey.startsWith('ip:') && mac) {
          this.byKey.delete(existingKey)
          existing.mac = mac
          existing.vendor = lookupVendor(mac)
          this.byKey.set(key, existing)
          device = existing
        }
      }
    }

    if (!device) {
      if (this.byKey.size >= this.maxDevices) this.evictOldest()
      device = {
        mac,
        ipv4: ip && !ip.includes(':') ? ip : null,
        ipv6: ip && ip.includes(':') ? ip : null,
        hostname: input.hostname ?? null,
        vendor: lookupVendor(mac),
        firstSeen: ts,
        lastSeen: ts,
        bytesUp: 0,
        bytesDown: 0,
        packetsUp: 0,
        packetsDown: 0,
        isLocal: true,
        deltaUp: 0,
        deltaDown: 0,
        deltaPackets: 0,
        fresh: true
      }
      this.byKey.set(key, device)
    }

    device.lastSeen = Math.max(device.lastSeen, ts)
    if (ip) {
      if (ip.includes(':')) device.ipv6 = ip
      else device.ipv4 = ip
      this.ipIndex.set(ip, key)
    }
    if (input.hostname && !device.hostname) device.hostname = input.hostname
    if (mac && !device.mac) {
      device.mac = mac
      device.vendor = lookupVendor(mac)
    }
    return device
  }

  addTraffic(device: TrackedDevice, bytes: number, upload: boolean): void {
    if (upload) {
      device.bytesUp += bytes
      device.packetsUp += 1
      device.deltaUp += bytes
    } else {
      device.bytesDown += bytes
      device.packetsDown += 1
      device.deltaDown += bytes
    }
    device.deltaPackets += 1
  }

  /** Returns devices that are new since the last call, clearing the flag. */
  drainNew(): TrackedDevice[] {
    const out: TrackedDevice[] = []
    for (const device of this.byKey.values()) {
      if (!device.fresh) continue
      device.fresh = false
      out.push({ ...device })
    }
    return out
  }

  drainDeltas(): Array<{ device: TrackedDevice; up: number; down: number; packets: number }> {
    const out: Array<{ device: TrackedDevice; up: number; down: number; packets: number }> = []
    for (const device of this.byKey.values()) {
      if (device.deltaPackets === 0) continue
      out.push({ device, up: device.deltaUp, down: device.deltaDown, packets: device.deltaPackets })
      device.deltaUp = 0
      device.deltaDown = 0
      device.deltaPackets = 0
    }
    return out
  }

  private evictOldest(): void {
    let oldestKey: string | null = null
    let oldestTs = Infinity
    for (const [key, device] of this.byKey) {
      if (device.lastSeen < oldestTs) {
        oldestTs = device.lastSeen
        oldestKey = key
      }
    }
    if (!oldestKey) return
    const device = this.byKey.get(oldestKey)
    this.byKey.delete(oldestKey)
    if (device?.ipv4) this.ipIndex.delete(device.ipv4)
    if (device?.ipv6) this.ipIndex.delete(device.ipv6)
  }
}
