import { describe, expect, it } from 'vitest'
import { parsePacket } from '../src/backend/parser/packet.js'
import { parseDns } from '../src/backend/parser/dns.js'
import { parseHttp, summarizeHttp } from '../src/backend/parser/http.js'
import { parseTls } from '../src/backend/parser/tls.js'
import { parseDhcp } from '../src/backend/parser/dhcp.js'
import {
  arpFrame,
  dhcpPacket,
  dnsQuery,
  dnsResponse,
  ethernet,
  httpRequest,
  ipv4Packet,
  ipv6Packet,
  MAC_A,
  MAC_B,
  tcpSegment,
  tlsApplicationData,
  tlsClientHello,
  udpDatagram
} from './fixtures.js'

const now = 1_700_000_000_000

describe('ethernet + IPv4 + TCP', () => {
  it('extracts addresses, ports and flags', () => {
    const frame = ethernet(0x0800, ipv4Packet(6, '192.168.1.15', '142.250.1.1', tcpSegment(51000, 443, new Uint8Array(0), { syn: true })))
    const packet = parsePacket(frame, now, frame.length)

    expect(packet.network).toBe('IPv4')
    expect(packet.srcIp).toBe('192.168.1.15')
    expect(packet.dstIp).toBe('142.250.1.1')
    expect(packet.transport).toBe('TCP')
    expect(packet.srcPort).toBe(51000)
    expect(packet.dstPort).toBe(443)
    expect(packet.tcpFlags?.syn).toBe(true)
    expect(packet.tcpFlags?.ack).toBe(false)
    expect(packet.ethSrc).toBe('AA:BB:CC:DD:EE:FF')
  })

  it('reads a VLAN-tagged frame', () => {
    const inner = ipv4Packet(17, '10.0.0.5', '10.0.0.6', udpDatagram(1234, 5678, new Uint8Array(4)))
    const frame = new Uint8Array(14 + 4 + inner.length)
    frame.set(MAC_B, 0)
    frame.set(MAC_A, 6)
    frame.set([0x81, 0x00, 0x00, 0x64, 0x08, 0x00], 12) // VLAN id 100, then IPv4
    frame.set(inner, 18)

    const packet = parsePacket(frame, now, frame.length)
    expect(packet.vlanId).toBe(100)
    expect(packet.srcIp).toBe('10.0.0.5')
    expect(packet.transport).toBe('UDP')
  })

  it('does not treat a non-first fragment as carrying ports', () => {
    const payload = tcpSegment(80, 51000, new Uint8Array(8))
    const packet = ipv4Packet(6, '1.1.1.1', '2.2.2.2', payload)
    packet[6] = 0x00
    packet[7] = 0x25 // fragment offset != 0
    const parsed = parsePacket(ethernet(0x0800, packet), now, 100)
    expect(parsed.transport).toBe('OTHER')
    expect(parsed.srcPort).toBe(0)
  })
})

describe('IPv6', () => {
  it('parses addresses and the transport header', () => {
    const src = new Uint8Array(16)
    src[0] = 0x20
    src[1] = 0x01
    src[15] = 0x01
    const dst = new Uint8Array(16)
    dst[0] = 0x20
    dst[1] = 0x01
    dst[15] = 0x02

    const frame = ethernet(0x86dd, ipv6Packet(6, src, dst, tcpSegment(40000, 443, new Uint8Array(0), { ack: true })))
    const packet = parsePacket(frame, now, frame.length)

    expect(packet.network).toBe('IPv6')
    expect(packet.srcIp).toBe('2001::1')
    expect(packet.dstIp).toBe('2001::2')
    expect(packet.transport).toBe('TCP')
    expect(packet.dstPort).toBe(443)
  })
})

describe('ARP', () => {
  it('parses a request', () => {
    const frame = arpFrame(1, MAC_A, '192.168.1.10', new Uint8Array(6), '192.168.1.1')
    const packet = parsePacket(frame, now, frame.length)

    expect(packet.transport).toBe('ARP')
    expect(packet.arp?.operation).toBe('request')
    expect(packet.arp?.senderIp).toBe('192.168.1.10')
    expect(packet.arp?.targetIp).toBe('192.168.1.1')
  })
})

describe('DNS', () => {
  it('parses a query', () => {
    const dns = parseDns(dnsQuery(0x1234, 'example.com'))
    expect(dns?.isResponse).toBe(false)
    expect(dns?.questions[0]).toEqual({ name: 'example.com', type: 'A' })
  })

  it('resolves a compressed answer name and its address', () => {
    const dns = parseDns(dnsResponse(0x1234, 'example.com', '93.184.216.34'))
    expect(dns?.isResponse).toBe(true)
    expect(dns?.responseCode).toBe('NOERROR')
    expect(dns?.answers[0].data).toBe('93.184.216.34')
    expect(dns?.answers[0].type).toBe('A')
  })

  it('is identified end to end from a UDP packet', () => {
    const frame = ethernet(0x0800, ipv4Packet(17, '192.168.1.15', '8.8.8.8', udpDatagram(50000, 53, dnsQuery(1, 'test.local'))))
    const packet = parsePacket(frame, now, frame.length)
    expect(packet.appProtocol).toBe('DNS')
    expect(packet.confidence).toBe('header')
    expect(packet.encrypted).toBe(false)
  })

  it('rejects random bytes rather than guessing', () => {
    expect(parseDns(Uint8Array.from([1, 2, 3]))).toBeNull()
  })
})

describe('TLS', () => {
  it('reads the SNI from a ClientHello', () => {
    const tls = parseTls(tlsClientHello('www.example.com'))
    expect(tls?.kind).toBe('client-hello')
    expect(tls?.sni).toBe('www.example.com')
  })

  it('marks application data as encrypted without reading it', () => {
    const frame = ethernet(0x0800, ipv4Packet(6, '192.168.1.15', '142.250.1.1', tcpSegment(51000, 443, tlsApplicationData())))
    const packet = parsePacket(frame, now, frame.length)
    expect(packet.appProtocol).toBe('HTTPS/TLS')
    expect(packet.encrypted).toBe(true)
    expect(packet.app?.protocol).toBe('TLS')
  })
})

describe('HTTP redaction', () => {
  it('keeps allowlisted headers and drops everything else', () => {
    const http = parseHttp(
      httpRequest('GET /account?token=SECRET123 HTTP/1.1', [
        'Host: example.com',
        'User-Agent: test-agent',
        'Cookie: session=abcdef',
        'Authorization: Bearer VERYSECRET'
      ])
    )

    expect(http).not.toBeNull()
    expect(http!.host).toBe('example.com')
    expect(http!.path).toBe('/account?[query redacted]')
    expect(http!.redacted).toBe(true)

    const headerNames = http!.safeHeaders.map(([name]) => name)
    expect(headerNames).toContain('host')
    expect(headerNames).toContain('user-agent')
    expect(headerNames).not.toContain('cookie')
    expect(headerNames).not.toContain('authorization')

    const serialized = JSON.stringify(http)
    expect(serialized).not.toContain('SECRET123')
    expect(serialized).not.toContain('abcdef')
    expect(serialized).not.toContain('VERYSECRET')
  })

  it('strips the query string from a referer', () => {
    const http = parseHttp(httpRequest('GET / HTTP/1.1', ['Host: a.test', 'Referer: http://b.test/p?sid=LEAK']))
    expect(JSON.stringify(http)).not.toContain('LEAK')
  })

  it('summarises a request without leaking the body', () => {
    const raw = httpRequest('POST /login HTTP/1.1', ['Host: a.test', 'Content-Type: application/json'])
    const withBody = new Uint8Array(raw.length + 20)
    withBody.set(raw)
    withBody.set(Uint8Array.from(Buffer.from('{"pw":"hunter2"}   ', 'ascii')), raw.length)

    const http = parseHttp(withBody)!
    const summary = summarizeHttp(http)
    expect(summary).toContain('POST /login')
    expect(summary).toContain('Host: a.test')
    expect(summary).toContain('[Sensitive data redacted]')
    expect(summary).not.toContain('hunter2')
  })
})

describe('DHCP', () => {
  it('reads the client-supplied hostname', () => {
    const dhcp = parseDhcp(dhcpPacket('living-room-tv'))
    expect(dhcp?.hostname).toBe('living-room-tv')
    expect(dhcp?.messageType).toBe('REQUEST')
  })
})

describe('robustness', () => {
  it('never throws on truncated or random input', () => {
    const inputs = [
      new Uint8Array(0),
      new Uint8Array(3),
      ethernet(0x0800, new Uint8Array(4)),
      Uint8Array.from({ length: 64 }, (_, i) => (i * 37) % 256)
    ]
    for (const input of inputs) {
      expect(() => parsePacket(input, now, input.length)).not.toThrow()
    }
  })
})
