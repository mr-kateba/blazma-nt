import { describe, expect, it } from 'vitest'
import { FlowTracker, nextTcpState } from '../src/backend/flows/tracker.js'
import { parsePacket } from '../src/backend/parser/packet.js'
import { DeviceRegistry } from '../src/backend/devices/registry.js'
import { lookupVendor } from '../src/backend/devices/vendors.js'
import { PcapStreamReader } from '../src/backend/capture/pcapStream.js'
import { pcapFormatArgs } from '../src/backend/capture/dumpcapSource.js'
import { flowKey, inSubnet, ipv6ToString, isPrivateIp, normalizeMac } from '../src/backend/utils/net.js'
import { ethernet, ipv4Packet, MAC_A, MAC_B, pcapStream, tcpSegment, udpDatagram } from './fixtures.js'

const now = 1_700_000_000_000

function tcpPacket(
  src: string,
  dst: string,
  srcPort: number,
  dstPort: number,
  bytesLength: number,
  flags: Parameters<typeof tcpSegment>[3] = {},
  ts = now
): ReturnType<typeof parsePacket> {
  const frame = ethernet(0x0800, ipv4Packet(6, src, dst, tcpSegment(srcPort, dstPort, new Uint8Array(bytesLength), flags)))
  return parsePacket(frame, ts, frame.length)
}

describe('flow tracker', () => {
  it('collapses both directions onto one record', () => {
    const tracker = new FlowTracker()
    const a = tracker.update({
      packet: tcpPacket('192.168.1.15', '93.184.216.34', 51000, 443, 100, { syn: true }),
      srcIsLocal: true,
      dstIsLocal: false,
      deviceMac: 'AA:BB:CC:DD:EE:FF',
      deviceIp: '192.168.1.15'
    })
    const b = tracker.update({
      packet: tcpPacket('93.184.216.34', '192.168.1.15', 443, 51000, 500, { syn: true, ack: true }),
      srcIsLocal: false,
      dstIsLocal: true,
      deviceMac: 'AA:BB:CC:DD:EE:FF',
      deviceIp: '192.168.1.15'
    })

    expect(tracker.size).toBe(1)
    expect(a.key).toBe(b.key)
    expect(b.state).toBe('ESTABLISHED')
    expect(b.packetsUp).toBe(1)
    expect(b.packetsDown).toBe(1)
    expect(b.bytesUp).toBeGreaterThan(0)
    expect(b.bytesDown).toBeGreaterThan(b.bytesUp)
    expect(b.direction).toBe('up')
  })

  it('orients the local device as the source', () => {
    const tracker = new FlowTracker()
    const flow = tracker.update({
      packet: tcpPacket('93.184.216.34', '192.168.1.15', 443, 51000, 200),
      srcIsLocal: false,
      dstIsLocal: true,
      deviceMac: null,
      deviceIp: '192.168.1.15'
    })
    expect(flow.srcIp).toBe('192.168.1.15')
    expect(flow.dstIp).toBe('93.184.216.34')
    expect(flow.dstPort).toBe(443)
    expect(flow.direction).toBe('down')
  })

  it('drains deltas once and then resets them', () => {
    const tracker = new FlowTracker()
    tracker.update({
      packet: tcpPacket('192.168.1.15', '1.1.1.1', 4000, 80, 100),
      srcIsLocal: true,
      dstIsLocal: false,
      deviceMac: null,
      deviceIp: '192.168.1.15'
    })
    expect(tracker.drainDeltas()).toHaveLength(1)
    expect(tracker.drainDeltas()).toHaveLength(0)
  })

  it('expires idle flows', () => {
    const tracker = new FlowTracker()
    tracker.update({
      packet: tcpPacket('192.168.1.15', '1.1.1.1', 4000, 80, 100, {}, now),
      srcIsLocal: true,
      dstIsLocal: false,
      deviceMac: null,
      deviceIp: '192.168.1.15'
    })
    expect(tracker.expire(now + 1000)).toHaveLength(0)
    expect(tracker.expire(now + 200_000)).toHaveLength(1)
    expect(tracker.size).toBe(0)
  })

  it('bounds the table under a port scan', () => {
    const tracker = new FlowTracker(50)
    for (let port = 1; port <= 400; port++) {
      tracker.update({
        packet: tcpPacket('192.168.1.99', '192.168.1.1', 40000, port, 60, { syn: true }, now + port),
        srcIsLocal: true,
        dstIsLocal: true,
        deviceMac: null,
        deviceIp: '192.168.1.99'
      })
    }
    expect(tracker.size).toBeLessThanOrEqual(50)
  })

  it('lets a header-derived protocol override a port hint', () => {
    const tracker = new FlowTracker()
    // Port 8080 gives the HTTP hint first.
    const first = tracker.update({
      packet: tcpPacket('192.168.1.15', '5.5.5.5', 3000, 8080, 0),
      srcIsLocal: true,
      dstIsLocal: false,
      deviceMac: null,
      deviceIp: '192.168.1.15'
    })
    expect(first.confidence).toBe('port-hint')

    // A TLS record on the same 5-tuple is authoritative.
    const tlsFrame = ethernet(
      0x0800,
      ipv4Packet(6, '192.168.1.15', '5.5.5.5', tcpSegment(3000, 8080, Uint8Array.of(0x17, 0x03, 0x03, 0x00, 0x20, ...new Uint8Array(32))))
    )
    const second = tracker.update({
      packet: parsePacket(tlsFrame, now, tlsFrame.length),
      srcIsLocal: true,
      dstIsLocal: false,
      deviceMac: null,
      deviceIp: '192.168.1.15'
    })
    expect(second.confidence).toBe('header')
    expect(second.appProtocol).toBe('HTTPS/TLS')
    expect(second.encryption).toBe('encrypted')
  })
})

describe('tcp state machine', () => {
  it('follows the observed flags', () => {
    expect(nextTcpState('NEW', { syn: true, ack: false, fin: false, rst: false })).toBe('NEW')
    expect(nextTcpState('NEW', { syn: true, ack: true, fin: false, rst: false })).toBe('ESTABLISHED')
    expect(nextTcpState('NEW', { syn: false, ack: true, fin: false, rst: false })).toBe('ESTABLISHED')
    expect(nextTcpState('ESTABLISHED', { syn: false, ack: true, fin: true, rst: false })).toBe('CLOSING')
    expect(nextTcpState('CLOSING', { syn: false, ack: true, fin: true, rst: false })).toBe('TIME_WAIT')
    expect(nextTcpState('ESTABLISHED', { syn: false, ack: false, fin: false, rst: true })).toBe('CLOSED')
  })
})

describe('device registry', () => {
  it('tracks a local device and its vendor', () => {
    const registry = new DeviceRegistry()
    const device = registry.observe({ mac: 'B8:27:EB:11:22:33', ip: '192.168.1.50', ts: now, isLocal: true })
    expect(device?.vendor).toBe('Raspberry Pi Foundation')
    expect(registry.size).toBe(1)
  })

  it('ignores public addresses, which are destinations rather than devices', () => {
    const registry = new DeviceRegistry()
    expect(registry.observe({ mac: null, ip: '93.184.216.34', ts: now, isLocal: false })).toBeNull()
    expect(registry.size).toBe(0)
  })

  it('skips broadcast and multicast addresses', () => {
    const registry = new DeviceRegistry()
    expect(registry.observe({ mac: null, ip: '255.255.255.255', ts: now, isLocal: true })).toBeNull()
    expect(registry.observe({ mac: null, ip: '224.0.0.251', ts: now, isLocal: true })).toBeNull()
  })

  it('reports each device as new exactly once', () => {
    const registry = new DeviceRegistry()
    registry.observe({ mac: 'AA:BB:CC:DD:EE:FF', ip: '192.168.1.10', ts: now, isLocal: true })
    expect(registry.drainNew()).toHaveLength(1)
    registry.observe({ mac: 'AA:BB:CC:DD:EE:FF', ip: '192.168.1.10', ts: now + 5, isLocal: true })
    expect(registry.drainNew()).toHaveLength(0)
  })

  it('flags randomized MACs instead of inventing a vendor', () => {
    expect(lookupVendor('DA:A1:19:00:00:01')).toBe('Randomized MAC (private address)')
    expect(lookupVendor('01:02:03:04:05:06')).toBeNull()
  })
})

describe('pcap stream reader', () => {
  it('reads packets split across arbitrary chunk boundaries', () => {
    const frameA = ethernet(0x0800, ipv4Packet(17, '10.0.0.1', '10.0.0.2', udpDatagram(1, 2, new Uint8Array(10))))
    const frameB = ethernet(0x0800, ipv4Packet(6, '10.0.0.1', '10.0.0.3', tcpSegment(3, 4, new Uint8Array(20))))
    const stream = pcapStream([frameA, frameB])

    const reader = new PcapStreamReader()
    const collected: number[] = []
    for (let i = 0; i < stream.length; i += 7) {
      for (const packet of reader.push(stream.subarray(i, Math.min(i + 7, stream.length)))) {
        collected.push(packet.data.length)
      }
    }

    expect(reader.error).toBeNull()
    expect(reader.linkType).toBe(1)
    expect(collected).toEqual([frameA.length, frameB.length])
  })

  it('reports pcapng rather than mis-parsing it', () => {
    const reader = new PcapStreamReader()
    reader.push(Uint8Array.from([0x0a, 0x0d, 0x0d, 0x0a, ...new Array(20).fill(0)]))
    expect(reader.error).toContain('pcapng')
  })
})

describe('net helpers', () => {
  it('computes subnet membership', () => {
    expect(inSubnet('192.168.1.50', '192.168.1.1', 24)).toBe(true)
    expect(inSubnet('192.168.2.50', '192.168.1.1', 24)).toBe(false)
    expect(inSubnet('10.1.2.3', '10.0.0.1', 8)).toBe(true)
  })

  it('classifies private addresses', () => {
    expect(isPrivateIp('192.168.1.1')).toBe(true)
    expect(isPrivateIp('172.16.5.4')).toBe(true)
    expect(isPrivateIp('172.32.5.4')).toBe(false)
    expect(isPrivateIp('8.8.8.8')).toBe(false)
    expect(isPrivateIp('fe80::1')).toBe(true)
  })

  it('produces one key per conversation regardless of direction', () => {
    const forward = flowKey('1.1.1.1', 100, '2.2.2.2', 200, 'TCP')
    const reverse = flowKey('2.2.2.2', 200, '1.1.1.1', 100, 'TCP')
    expect(forward.key).toBe(reverse.key)
  })

  it('compresses IPv6 the RFC 5952 way', () => {
    const buf = new Uint8Array(16)
    buf[0] = 0x20
    buf[1] = 0x01
    buf[15] = 0x01
    expect(ipv6ToString(buf, 0)).toBe('2001::1')
  })

  it('normalises MAC formatting', () => {
    expect(normalizeMac('aa-bb-cc-dd-ee-ff')).toBe('AA:BB:CC:DD:EE:FF')
    expect(normalizeMac('nonsense')).toBeNull()
  })
})

describe('fixtures sanity', () => {
  it('builds distinct MAC constants', () => {
    expect(MAC_A).not.toEqual(MAC_B)
  })
})

describe('dumpcap format flag', () => {
  it('uses -F pcap on Wireshark 4.2 and newer', () => {
    expect(pcapFormatArgs('Dumpcap (Wireshark) 4.6.7 (v4.6.7-0-gb439fb7b47a9)')).toEqual(['-F', 'pcap'])
    expect(pcapFormatArgs('Dumpcap (Wireshark) 4.2.0')).toEqual(['-F', 'pcap'])
    expect(pcapFormatArgs('Dumpcap (Wireshark) 5.0.1')).toEqual(['-F', 'pcap'])
  })

  it('falls back to -P on older builds and when the version is unknown', () => {
    expect(pcapFormatArgs('Dumpcap (Wireshark) 4.0.8')).toEqual(['-P'])
    expect(pcapFormatArgs('Dumpcap (Wireshark) 3.6.2')).toEqual(['-P'])
    expect(pcapFormatArgs(null)).toEqual(['-P'])
    expect(pcapFormatArgs('unparseable banner')).toEqual(['-P'])
  })
})
