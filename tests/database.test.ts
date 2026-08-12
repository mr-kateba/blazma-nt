import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Store } from '../src/backend/database/store.js'
import { AlertEngine } from '../src/backend/alerts/engine.js'
import { buildReport } from '../src/backend/analytics/report.js'
import { validateBpfFilter, validateInterfaceId, validateSavePath, ValidationError } from '../src/backend/security/validate.js'
import { scrub } from '../src/backend/utils/logger.js'
import { renderTablePdf } from '../src/backend/utils/pdf.js'
import { codedError, parseCoded } from '../src/shared/errors.js'

let dir: string
let store: Store
const now = Date.now()

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'blazma-test-'))
  store = new Store(join(dir, 'test.db'))
})

afterEach(() => {
  store.close()
  rmSync(dir, { recursive: true, force: true })
})

describe('migrations', () => {
  it('creates every expected table', () => {
    const names = store.tableStats().map((t) => t.name)
    for (const table of [
      'devices',
      'flows',
      'dns_queries',
      'unencrypted_events',
      'tls_sessions',
      'traffic_stats',
      'device_stats',
      'protocol_stats',
      'alerts',
      'settings',
      'logs',
      'interfaces'
    ]) {
      expect(names).toContain(table)
    }
  })

  it('is idempotent when reopened', () => {
    const path = store.path
    store.close()
    const reopened = new Store(path)
    expect(reopened.tableStats().length).toBeGreaterThan(0)
    reopened.close()
    store = new Store(path)
  })
})

describe('devices', () => {
  const device = {
    mac: 'AA:BB:CC:DD:EE:FF',
    ipv4: '192.168.1.10',
    ipv6: null,
    hostname: 'phone',
    vendor: 'Samsung',
    label: null,
    firstSeen: now - 60_000,
    lastSeen: now,
    bytesUp: 1000,
    bytesDown: 5000,
    packetsUp: 10,
    packetsDown: 20,
    isLocal: true,
    paused: false,
    ignored: false
  }

  it('upserts by MAC instead of duplicating', () => {
    store.upsertDevices([device])
    store.upsertDevices([{ ...device, bytesDown: 9000, lastSeen: now + 1000 }])
    const rows = store.listDevices(true, now - 120_000)
    expect(rows).toHaveLength(1)
    expect(rows[0].bytesDown).toBe(9000)
  })

  it('computes online state from the cutoff', () => {
    store.upsertDevices([device])
    expect(store.listDevices(true, now - 1000)[0].online).toBe(true)
    expect(store.listDevices(true, now + 1000)[0].online).toBe(false)
  })

  it('applies user flags and hides ignored devices', () => {
    store.upsertDevices([device])
    const id = store.listDevices(true, 0)[0].id
    store.setDeviceFlags(id, { ignored: true, paused: true, label: 'Kitchen TV' })
    expect(store.listDevices(true, 0)[0].label).toBe('Kitchen TV')
    expect(store.listDevices(false, 0)).toHaveLength(0)
  })
})

describe('flows', () => {
  const flow = {
    key: 'TCP|192.168.1.10|4000|93.184.216.34|443',
    srcIp: '192.168.1.10',
    srcPort: 4000,
    dstIp: '93.184.216.34',
    dstPort: 443,
    transport: 'TCP' as const,
    appProtocol: 'HTTPS/TLS',
    confidence: 'header',
    encryption: 'encrypted',
    direction: 'up',
    state: 'ESTABLISHED',
    firstSeen: now - 5000,
    lastSeen: now,
    bytesUp: 1500,
    bytesDown: 22000,
    packetsUp: 12,
    packetsDown: 30,
    serverName: 'example.com',
    remoteHostname: null,
    deviceMac: 'AA:BB:CC:DD:EE:FF',
    deviceIp: '192.168.1.10'
  }

  it('round-trips and filters', () => {
    store.upsertFlows([flow])
    expect(store.queryFlows({ text: 'example' }).total).toBe(1)
    expect(store.queryFlows({ encryption: ['encrypted'] }).total).toBe(1)
    expect(store.queryFlows({ encryption: ['unencrypted'] }).total).toBe(0)
    expect(store.queryFlows({ port: 443 }).total).toBe(1)
    expect(store.queryFlows({ transport: ['UDP'] }).total).toBe(0)
  })

  it('treats search text as data, not SQL', () => {
    store.upsertFlows([flow])
    const evil = "'; DROP TABLE flows; --"
    expect(store.queryFlows({ text: evil }).total).toBe(0)
    // The table must still be there.
    expect(store.queryFlows({}).total).toBe(1)
  })

  it('backfills hostnames learned from DNS', () => {
    store.upsertFlows([{ ...flow, serverName: null }])
    store.applyDnsHostname('93.184.216.34', 'example.com')
    expect(store.queryFlows({}).rows[0].remoteHostname).toBe('example.com')
  })

  it('ranks destinations by bytes', () => {
    store.upsertFlows([
      flow,
      { ...flow, key: 'k2', dstIp: '1.1.1.1', serverName: 'one.one', bytesDown: 999999 }
    ])
    expect(store.topDestinations(now - 60_000)[0].label).toBe('one.one')
  })
})

describe('statistics and retention', () => {
  it('buckets a traffic series', () => {
    for (let i = 0; i < 10; i++) {
      store.insertTrafficSample({ ts: now - i * 1000, bytesUp: 100, bytesDown: 200, packets: 5 })
    }
    const series = store.trafficSeries(now - 20_000, now + 1000, 5000)
    expect(series.length).toBeGreaterThan(0)
    expect(series.reduce((sum, s) => sum + s.bytesUp, 0)).toBe(1000)
  })

  it('deletes only rows older than the policy window', () => {
    store.insertTrafficSample({ ts: now - 10 * 24 * 60 * 60 * 1000, bytesUp: 1, bytesDown: 1, packets: 1 })
    store.insertTrafficSample({ ts: now, bytesUp: 1, bytesDown: 1, packets: 1 })
    store.applyRetention('7d', now)
    expect(store.trafficSeries(0, now + 1000, 1000)).toHaveLength(1)
  })

  it('keeps everything under the unlimited policy', () => {
    store.insertTrafficSample({ ts: 1000, bytesUp: 1, bytesDown: 1, packets: 1 })
    expect(store.applyRetention('unlimited', now)).toBe(0)
  })

  it('builds an analytics report from stored aggregates', () => {
    store.insertTrafficSample({ ts: now - 1000, bytesUp: 1000, bytesDown: 3000, packets: 40 })
    const report = buildReport(store, '1h', now)
    expect(report.totalBytes).toBe(4000)
    expect(report.bytesUp).toBe(1000)
    expect(report.upDownRatio).toBeCloseTo(1000 / 3000)
    expect(report.avgBandwidthBps).toBeGreaterThan(0)
  })
})

describe('alerts store', () => {
  it('inserts, acknowledges and clears', () => {
    const inserted = store.insertAlerts([
      {
        ts: now,
        kind: 'new-device',
        severity: 'INFO',
        title: 'New device',
        reason: 'because',
        deviceIp: '192.168.1.5',
        deviceMac: null,
        acknowledged: false,
        details: null
      }
    ])
    expect(inserted[0].id).toBeGreaterThan(0)
    expect(store.listAlerts({ onlyUnacked: true }).total).toBe(1)
    store.ackAlerts('all')
    expect(store.listAlerts({ onlyUnacked: true }).total).toBe(0)
    expect(store.purge('alerts')).toBe(1)
  })
})

describe('alert engine', () => {
  it('fires on a scan-shaped burst of distinct ports', () => {
    const engine = new AlertEngine()
    let fired = null
    for (let port = 1; port <= 40 && !fired; port++) {
      fired = engine.observeConnection('192.168.1.99', port, now)
    }
    expect(fired?.kind).toBe('port-scan-pattern')
    // The wording must stay descriptive, never accusatory.
    expect(fired?.reason).toContain('shape, not a verdict')
  })

  it('does not fire below the threshold', () => {
    const engine = new AlertEngine()
    for (let port = 1; port <= 5; port++) {
      expect(engine.observeConnection('192.168.1.99', port, now)).toBeNull()
    }
  })

  it('suppresses duplicate new-device alerts inside the cooldown', () => {
    const engine = new AlertEngine()
    const device = { mac: 'AA:BB:CC:DD:EE:FF', ipv4: '192.168.1.5', vendor: null }
    expect(engine.newDevice(device, now)).not.toBeNull()
    expect(engine.newDevice(device, now + 1000)).toBeNull()
  })

  it('needs a baseline before calling anything a spike', () => {
    const engine = new AlertEngine()
    expect(engine.observeBandwidth(50_000_000, now).some((a) => a.kind === 'traffic-spike')).toBe(false)
  })
})

describe('input validation', () => {
  it('accepts real Npcap device names and rejects anything else', () => {
    const valid = '\\Device\\NPF_{12345678-1234-1234-1234-123456789ABC}'
    expect(validateInterfaceId(valid)).toBe(valid)
    expect(() => validateInterfaceId('\\Device\\NPF_{x} & calc.exe')).toThrow(ValidationError)
    expect(() => validateInterfaceId('')).toThrow(ValidationError)
  })

  it('allows genuine BPF filters and blocks smuggled options', () => {
    expect(validateBpfFilter('tcp port 80 and host 192.168.1.10')).toBe('tcp port 80 and host 192.168.1.10')
    expect(validateBpfFilter('')).toBe('')
    expect(() => validateBpfFilter('-w C:\\evil.pcap')).toThrow(ValidationError)
    expect(() => validateBpfFilter('tcp; calc.exe')).toThrow(ValidationError)
    expect(() => validateBpfFilter('$(whoami)')).toThrow(ValidationError)
    expect(() => validateBpfFilter('`id`')).toThrow(ValidationError)
  })

  it('requires an absolute path with an allowed extension', () => {
    expect(validateSavePath('C:\\temp\\a.pcap', ['.pcap'])).toContain('a.pcap')
    expect(() => validateSavePath('relative.pcap', ['.pcap'])).toThrow(ValidationError)
    expect(() => validateSavePath('C:\\temp\\a.exe', ['.pcap'])).toThrow(ValidationError)
  })
})

describe('log scrubbing', () => {
  it('removes credentials that reach the logger', () => {
    const scrubbed = scrub('GET / Authorization: Bearer abc123 cookie: sid=xyz password=hunter2')
    expect(scrubbed).not.toContain('abc123')
    expect(scrubbed).not.toContain('xyz')
    expect(scrubbed).not.toContain('hunter2')
    expect(scrubbed).toContain('[redacted]')
  })
})

describe('pdf export', () => {
  it('produces a structurally valid document', () => {
    const pdf = renderTablePdf({
      title: 'Test report',
      subtitle: 'generated by a test',
      columns: ['A', 'B'],
      rows: Array.from({ length: 120 }, (_, i) => [`row ${i}`, String(i)])
    })
    const text = pdf.toString('latin1')
    expect(text.startsWith('%PDF-1.4')).toBe(true)
    expect(text).toContain('/Type /Catalog')
    expect(text.trimEnd().endsWith('%%EOF')).toBe(true)
    // 120 rows must have spilled onto more than one page.
    expect(text.match(/\/Type \/Page[^s]/g)?.length ?? 0).toBeGreaterThan(1)
  })
})

describe('settings persistence', () => {
  it('stores and reloads a value', () => {
    store.setSetting('k', 'v1')
    store.setSetting('k', 'v2')
    expect(store.getSetting('k')).toBe('v2')
    expect(store.getSetting('missing')).toBeNull()
  })
})

describe('coded errors', () => {
  it('round-trips a code and its fallback text', () => {
    const err = codedError('E_NPCAP_MISSING', 'Npcap is required.')
    const parsed = parseCoded(err.message)
    expect(parsed.code).toBe('E_NPCAP_MISSING')
    expect(parsed.text).toBe('Npcap is required.')
  })

  it('passes through a message that carries no code', () => {
    const parsed = parseCoded('dumpcap exited with code 2')
    expect(parsed.code).toBeNull()
    expect(parsed.text).toBe('dumpcap exited with code 2')
  })

  it('does not mistake an unknown prefix for a code', () => {
    const parsed = parseCoded('SOMETHING_ELSE|detail')
    expect(parsed.code).toBeNull()
    expect(parsed.text).toBe('SOMETHING_ELSE|detail')
  })

  it('keeps a pipe that appears inside the fallback text', () => {
    const parsed = parseCoded(codedError('E_CAPTURE_FAILED', 'filter "a | b" rejected').message)
    expect(parsed.code).toBe('E_CAPTURE_FAILED')
    expect(parsed.text).toBe('filter "a | b" rejected')
  })
})
