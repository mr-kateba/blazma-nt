import { openDatabase, type SqliteDb, type SqlValue } from './driver.js'
import { runMigrations } from './migrations.js'
import type {
  AlertRecord,
  AlertSeverity,
  DeviceRecord,
  DnsQueryRecord,
  FlowQuery,
  FlowRecord,
  LogEntry,
  LogLevel,
  ProtocolStat,
  RetentionPolicy,
  TlsSessionRecord,
  TrafficSample,
  TransportProtocol,
  UnencryptedEvent
} from '../../shared/types.js'

/** Rows we accumulate in memory and flush in one transaction per tick. */
export interface FlowUpsert {
  key: string
  srcIp: string
  srcPort: number
  dstIp: string
  dstPort: number
  transport: TransportProtocol
  appProtocol: string
  confidence: string
  encryption: string
  direction: string
  state: string
  firstSeen: number
  lastSeen: number
  bytesUp: number
  bytesDown: number
  packetsUp: number
  packetsDown: number
  serverName: string | null
  remoteHostname: string | null
  deviceMac: string | null
  deviceIp: string | null
}

const RETENTION_MS: Record<RetentionPolicy, number | null> = {
  '1d': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
  '90d': 90 * 24 * 60 * 60 * 1000,
  unlimited: null
}

/**
 * All SQL lives here. Every statement is prepared with bound parameters —
 * no string interpolation of caller-supplied values anywhere in this file.
 */
export class Store {
  readonly db: SqliteDb
  readonly path: string

  constructor(path: string) {
    this.path = path
    this.db = openDatabase(path)
    runMigrations(this.db)
  }

  close(): void {
    this.db.close()
  }

  /* ---------------------------------------------------------------- */
  /* Settings                                                          */
  /* ---------------------------------------------------------------- */

  getSetting(key: string): string | null {
    const row = this.db.prepare('SELECT value FROM settings WHERE key = ?').get<{ value: string }>([key])
    return row?.value ?? null
  }

  setSetting(key: string, value: string): void {
    this.db
      .prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
      .run([key, value])
  }

  /* ---------------------------------------------------------------- */
  /* Devices                                                           */
  /* ---------------------------------------------------------------- */

  upsertDevices(devices: Array<Omit<DeviceRecord, 'id' | 'online' | 'connections'>>): void {
    if (devices.length === 0) return
    const stmt = this.db.prepare(`
      INSERT INTO devices (mac, ipv4, ipv6, hostname, vendor, label, first_seen, last_seen,
                           bytes_up, bytes_down, packets_up, packets_down, is_local)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(mac) DO UPDATE SET
        ipv4 = COALESCE(excluded.ipv4, devices.ipv4),
        ipv6 = COALESCE(excluded.ipv6, devices.ipv6),
        hostname = COALESCE(excluded.hostname, devices.hostname),
        vendor = COALESCE(excluded.vendor, devices.vendor),
        last_seen = MAX(excluded.last_seen, devices.last_seen),
        bytes_up = excluded.bytes_up,
        bytes_down = excluded.bytes_down,
        packets_up = excluded.packets_up,
        packets_down = excluded.packets_down
    `)
    this.db.transaction(() => {
      for (const d of devices) {
        stmt.run([
          d.mac,
          d.ipv4,
          d.ipv6,
          d.hostname,
          d.vendor,
          d.label,
          d.firstSeen,
          d.lastSeen,
          d.bytesUp,
          d.bytesDown,
          d.packetsUp,
          d.packetsDown,
          d.isLocal ? 1 : 0
        ])
      }
    })
  }

  listDevices(includeIgnored: boolean, onlineCutoff: number): DeviceRecord[] {
    const rows = this.db
      .prepare(
        `SELECT d.*, (SELECT COUNT(*) FROM flows f WHERE f.device_mac = d.mac AND f.last_seen > ?) AS conns
         FROM devices d ${includeIgnored ? '' : 'WHERE d.ignored = 0'}
         ORDER BY d.last_seen DESC`
      )
      .all<Record<string, SqlValue>>([onlineCutoff])
    return rows.map((r) => this.mapDevice(r, onlineCutoff))
  }

  getDevice(id: number, onlineCutoff: number): DeviceRecord | null {
    const row = this.db
      .prepare(
        `SELECT d.*, (SELECT COUNT(*) FROM flows f WHERE f.device_mac = d.mac AND f.last_seen > ?) AS conns
         FROM devices d WHERE d.id = ?`
      )
      .get<Record<string, SqlValue>>([onlineCutoff, id])
    return row ? this.mapDevice(row, onlineCutoff) : null
  }

  setDeviceFlags(id: number, flags: { paused?: boolean; ignored?: boolean; label?: string | null }): void {
    const sets: string[] = []
    const params: SqlValue[] = []
    if (flags.paused !== undefined) {
      sets.push('paused = ?')
      params.push(flags.paused ? 1 : 0)
    }
    if (flags.ignored !== undefined) {
      sets.push('ignored = ?')
      params.push(flags.ignored ? 1 : 0)
    }
    if (flags.label !== undefined) {
      sets.push('label = ?')
      params.push(flags.label)
    }
    if (sets.length === 0) return
    params.push(id)
    this.db.prepare(`UPDATE devices SET ${sets.join(', ')} WHERE id = ?`).run(params)
  }

  private mapDevice(r: Record<string, SqlValue>, onlineCutoff: number): DeviceRecord {
    return {
      id: Number(r.id),
      mac: (r.mac as string) ?? null,
      ipv4: (r.ipv4 as string) ?? null,
      ipv6: (r.ipv6 as string) ?? null,
      hostname: (r.hostname as string) ?? null,
      vendor: (r.vendor as string) ?? null,
      label: (r.label as string) ?? null,
      firstSeen: Number(r.first_seen),
      lastSeen: Number(r.last_seen),
      online: Number(r.last_seen) > onlineCutoff,
      bytesUp: Number(r.bytes_up),
      bytesDown: Number(r.bytes_down),
      packetsUp: Number(r.packets_up),
      packetsDown: Number(r.packets_down),
      connections: Number(r.conns ?? 0),
      isLocal: Number(r.is_local) === 1,
      paused: Number(r.paused) === 1,
      ignored: Number(r.ignored) === 1
    }
  }

  /* ---------------------------------------------------------------- */
  /* Flows                                                             */
  /* ---------------------------------------------------------------- */

  upsertFlows(flows: FlowUpsert[]): void {
    if (flows.length === 0) return
    const stmt = this.db.prepare(`
      INSERT INTO flows (key, src_ip, src_port, dst_ip, dst_port, transport, app_protocol, confidence,
                         encryption, direction, state, first_seen, last_seen, bytes_up, bytes_down,
                         packets_up, packets_down, server_name, remote_hostname, device_mac, device_ip)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        app_protocol = excluded.app_protocol,
        confidence = excluded.confidence,
        encryption = excluded.encryption,
        state = excluded.state,
        last_seen = excluded.last_seen,
        bytes_up = excluded.bytes_up,
        bytes_down = excluded.bytes_down,
        packets_up = excluded.packets_up,
        packets_down = excluded.packets_down,
        server_name = COALESCE(excluded.server_name, flows.server_name),
        remote_hostname = COALESCE(excluded.remote_hostname, flows.remote_hostname)
    `)
    this.db.transaction(() => {
      for (const f of flows) {
        stmt.run([
          f.key,
          f.srcIp,
          f.srcPort,
          f.dstIp,
          f.dstPort,
          f.transport,
          f.appProtocol,
          f.confidence,
          f.encryption,
          f.direction,
          f.state,
          f.firstSeen,
          f.lastSeen,
          f.bytesUp,
          f.bytesDown,
          f.packetsUp,
          f.packetsDown,
          f.serverName,
          f.remoteHostname,
          f.deviceMac,
          f.deviceIp
        ])
      }
    })
  }

  queryFlows(q: FlowQuery): { rows: FlowRecord[]; total: number } {
    const where: string[] = []
    const params: SqlValue[] = []

    if (q.text) {
      where.push(
        '(src_ip LIKE ? OR dst_ip LIKE ? OR server_name LIKE ? OR remote_hostname LIKE ? OR app_protocol LIKE ?)'
      )
      const like = `%${q.text}%`
      params.push(like, like, like, like, like)
    }
    if (q.transport?.length) {
      where.push(`transport IN (${q.transport.map(() => '?').join(',')})`)
      params.push(...q.transport)
    }
    if (q.appProtocol?.length) {
      where.push(`app_protocol IN (${q.appProtocol.map(() => '?').join(',')})`)
      params.push(...q.appProtocol)
    }
    if (q.encryption?.length) {
      where.push(`encryption IN (${q.encryption.map(() => '?').join(',')})`)
      params.push(...q.encryption)
    }
    if (q.direction?.length) {
      where.push(`direction IN (${q.direction.map(() => '?').join(',')})`)
      params.push(...q.direction)
    }
    if (q.deviceIp) {
      where.push('(device_ip = ? OR src_ip = ? OR dst_ip = ?)')
      params.push(q.deviceIp, q.deviceIp, q.deviceIp)
    }
    if (q.port !== undefined) {
      where.push('(src_port = ? OR dst_port = ?)')
      params.push(q.port, q.port)
    }
    if (q.from !== undefined) {
      where.push('last_seen >= ?')
      params.push(q.from)
    }
    if (q.to !== undefined) {
      where.push('first_seen <= ?')
      params.push(q.to)
    }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : ''
    const total = Number(
      this.db.prepare(`SELECT COUNT(*) AS n FROM flows ${whereSql}`).get<{ n: number }>(params)?.n ?? 0
    )

    // Sort column is chosen from a fixed set, never taken raw from the caller.
    const sortColumn =
      q.sortBy === 'bytes' ? '(bytes_up + bytes_down)' : q.sortBy === 'firstSeen' ? 'first_seen' : 'last_seen'
    const sortDir = q.sortDir === 'asc' ? 'ASC' : 'DESC'
    const limit = Math.min(Math.max(q.limit ?? 200, 1), 5000)
    const offset = Math.max(q.offset ?? 0, 0)

    const rows = this.db
      .prepare(`SELECT * FROM flows ${whereSql} ORDER BY ${sortColumn} ${sortDir} LIMIT ? OFFSET ?`)
      .all<Record<string, SqlValue>>([...params, limit, offset])

    return { rows: rows.map(mapFlow), total }
  }

  flowsForDevice(deviceIp: string, limit = 200): FlowRecord[] {
    return this.db
      .prepare('SELECT * FROM flows WHERE device_ip = ? OR src_ip = ? OR dst_ip = ? ORDER BY last_seen DESC LIMIT ?')
      .all<Record<string, SqlValue>>([deviceIp, deviceIp, deviceIp, limit])
      .map(mapFlow)
  }

  topDestinations(from: number, limit = 10): Array<{ label: string; bytes: number; connections: number }> {
    return this.db
      .prepare(
        `SELECT COALESCE(server_name, remote_hostname, dst_ip) AS label,
                SUM(bytes_up + bytes_down) AS bytes, COUNT(*) AS conns
         FROM flows WHERE last_seen >= ? AND direction != 'local'
         GROUP BY label ORDER BY bytes DESC LIMIT ?`
      )
      .all<{ label: string; bytes: number; conns: number }>([from, limit])
      .map((r) => ({ label: r.label, bytes: Number(r.bytes), connections: Number(r.conns) }))
  }

  topDestinationsForDevice(
    deviceIp: string,
    from: number,
    limit = 10
  ): Array<{ label: string; bytes: number; connections: number }> {
    return this.db
      .prepare(
        `SELECT COALESCE(server_name, remote_hostname, dst_ip) AS label,
                SUM(bytes_up + bytes_down) AS bytes, COUNT(*) AS conns
         FROM flows WHERE last_seen >= ? AND (device_ip = ? OR src_ip = ?)
         GROUP BY label ORDER BY bytes DESC LIMIT ?`
      )
      .all<{ label: string; bytes: number; conns: number }>([from, deviceIp, deviceIp, limit])
      .map((r) => ({ label: r.label, bytes: Number(r.bytes), connections: Number(r.conns) }))
  }

  /** Attach a hostname learned from an observed DNS answer to matching flows. */
  applyDnsHostname(ip: string, hostname: string): void {
    this.db
      .prepare('UPDATE flows SET remote_hostname = ? WHERE dst_ip = ? AND remote_hostname IS NULL')
      .run([hostname, ip])
  }

  /* ---------------------------------------------------------------- */
  /* DNS                                                               */
  /* ---------------------------------------------------------------- */

  insertDnsQueries(rows: Array<Omit<DnsQueryRecord, 'id'>>): void {
    if (rows.length === 0) return
    const stmt = this.db.prepare(
      `INSERT INTO dns_queries (ts, device_ip, device_mac, server, query, record_type, response, response_code, latency_ms)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    this.db.transaction(() => {
      for (const r of rows) {
        stmt.run([
          r.ts,
          r.deviceIp,
          r.deviceMac,
          r.server,
          r.query,
          r.recordType,
          r.response,
          r.responseCode,
          r.latencyMs
        ])
      }
    })
  }

  listDns(opts: { limit?: number; offset?: number; text?: string; deviceIp?: string }): {
    rows: DnsQueryRecord[]
    total: number
  } {
    const where: string[] = []
    const params: SqlValue[] = []
    if (opts.text) {
      where.push('(query LIKE ? OR response LIKE ?)')
      params.push(`%${opts.text}%`, `%${opts.text}%`)
    }
    if (opts.deviceIp) {
      where.push('device_ip = ?')
      params.push(opts.deviceIp)
    }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : ''
    const total = Number(
      this.db.prepare(`SELECT COUNT(*) AS n FROM dns_queries ${whereSql}`).get<{ n: number }>(params)?.n ?? 0
    )
    const limit = Math.min(Math.max(opts.limit ?? 200, 1), 5000)
    const rows = this.db
      .prepare(`SELECT * FROM dns_queries ${whereSql} ORDER BY ts DESC LIMIT ? OFFSET ?`)
      .all<Record<string, SqlValue>>([...params, limit, Math.max(opts.offset ?? 0, 0)])
      .map(
        (r): DnsQueryRecord => ({
          id: Number(r.id),
          ts: Number(r.ts),
          deviceIp: (r.device_ip as string) ?? null,
          deviceMac: (r.device_mac as string) ?? null,
          server: r.server as string,
          query: r.query as string,
          recordType: r.record_type as string,
          response: (r.response as string) ?? null,
          responseCode: (r.response_code as string) ?? null,
          latencyMs: r.latency_ms === null ? null : Number(r.latency_ms)
        })
      )
    return { rows, total }
  }

  dnsForDevice(deviceIp: string, limit = 100): DnsQueryRecord[] {
    return this.listDns({ deviceIp, limit }).rows
  }

  /* ---------------------------------------------------------------- */
  /* Unencrypted + TLS                                                 */
  /* ---------------------------------------------------------------- */

  insertUnencrypted(rows: Array<Omit<UnencryptedEvent, 'id'>>): void {
    if (rows.length === 0) return
    const stmt = this.db.prepare(
      `INSERT INTO unencrypted_events (ts, device_ip, device_mac, src_ip, src_port, dst_ip, dst_port, protocol, bytes, metadata, redacted)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    this.db.transaction(() => {
      for (const r of rows) {
        stmt.run([
          r.ts,
          r.deviceIp,
          r.deviceMac,
          r.srcIp,
          r.srcPort,
          r.dstIp,
          r.dstPort,
          r.protocol,
          r.bytes,
          r.metadata,
          r.redacted ? 1 : 0
        ])
      }
    })
  }

  listUnencrypted(opts: { limit?: number; offset?: number; text?: string }): {
    rows: UnencryptedEvent[]
    total: number
  } {
    const where: string[] = []
    const params: SqlValue[] = []
    if (opts.text) {
      where.push('(src_ip LIKE ? OR dst_ip LIKE ? OR protocol LIKE ? OR metadata LIKE ?)')
      const like = `%${opts.text}%`
      params.push(like, like, like, like)
    }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : ''
    const total = Number(
      this.db.prepare(`SELECT COUNT(*) AS n FROM unencrypted_events ${whereSql}`).get<{ n: number }>(params)?.n ?? 0
    )
    const rows = this.db
      .prepare(`SELECT * FROM unencrypted_events ${whereSql} ORDER BY ts DESC LIMIT ? OFFSET ?`)
      .all<Record<string, SqlValue>>([
        ...params,
        Math.min(Math.max(opts.limit ?? 200, 1), 5000),
        Math.max(opts.offset ?? 0, 0)
      ])
      .map(
        (r): UnencryptedEvent => ({
          id: Number(r.id),
          ts: Number(r.ts),
          deviceIp: (r.device_ip as string) ?? null,
          deviceMac: (r.device_mac as string) ?? null,
          srcIp: r.src_ip as string,
          srcPort: Number(r.src_port),
          dstIp: r.dst_ip as string,
          dstPort: Number(r.dst_port),
          protocol: r.protocol as string,
          bytes: Number(r.bytes),
          metadata: r.metadata as string,
          redacted: Number(r.redacted) === 1
        })
      )
    return { rows, total }
  }

  insertTlsSessions(rows: Array<Omit<TlsSessionRecord, 'id'>>): void {
    if (rows.length === 0) return
    const stmt = this.db.prepare(
      `INSERT INTO tls_sessions (ts, device_ip, server_ip, server_port, sni, version, cert_subject, cert_issuer, bytes, duration_ms)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    this.db.transaction(() => {
      for (const r of rows) {
        stmt.run([
          r.ts,
          r.deviceIp,
          r.serverIp,
          r.serverPort,
          r.sni,
          r.version,
          r.certSubject,
          r.certIssuer,
          r.bytes,
          r.durationMs
        ])
      }
    })
  }

  listTls(opts: { limit?: number; offset?: number; text?: string }): TlsSessionRecord[] {
    const where = opts.text ? 'WHERE sni LIKE ? OR server_ip LIKE ?' : ''
    const params: SqlValue[] = opts.text ? [`%${opts.text}%`, `%${opts.text}%`] : []
    return this.db
      .prepare(`SELECT * FROM tls_sessions ${where} ORDER BY ts DESC LIMIT ? OFFSET ?`)
      .all<Record<string, SqlValue>>([
        ...params,
        Math.min(Math.max(opts.limit ?? 200, 1), 5000),
        Math.max(opts.offset ?? 0, 0)
      ])
      .map((r) => ({
        id: Number(r.id),
        ts: Number(r.ts),
        deviceIp: (r.device_ip as string) ?? null,
        serverIp: r.server_ip as string,
        serverPort: Number(r.server_port),
        sni: (r.sni as string) ?? null,
        version: (r.version as string) ?? null,
        certSubject: (r.cert_subject as string) ?? null,
        certIssuer: (r.cert_issuer as string) ?? null,
        bytes: Number(r.bytes),
        durationMs: Number(r.duration_ms)
      }))
  }

  /* ---------------------------------------------------------------- */
  /* Stats                                                             */
  /* ---------------------------------------------------------------- */

  insertTrafficSample(s: TrafficSample): void {
    this.db
      .prepare(
        `INSERT INTO traffic_stats (ts, bytes_up, bytes_down, packets) VALUES (?, ?, ?, ?)
         ON CONFLICT(ts) DO UPDATE SET bytes_up = bytes_up + excluded.bytes_up,
                                       bytes_down = bytes_down + excluded.bytes_down,
                                       packets = packets + excluded.packets`
      )
      .run([s.ts, s.bytesUp, s.bytesDown, s.packets])
  }

  insertDeviceSamples(ts: number, rows: Array<{ deviceId: number; bytesUp: number; bytesDown: number; packets: number }>): void {
    if (rows.length === 0) return
    const stmt = this.db.prepare(
      `INSERT INTO device_stats (ts, device_id, bytes_up, bytes_down, packets) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(ts, device_id) DO UPDATE SET bytes_up = bytes_up + excluded.bytes_up,
                                                bytes_down = bytes_down + excluded.bytes_down,
                                                packets = packets + excluded.packets`
    )
    this.db.transaction(() => {
      for (const r of rows) stmt.run([ts, r.deviceId, r.bytesUp, r.bytesDown, r.packets])
    })
  }

  insertProtocolSamples(
    ts: number,
    rows: Array<{ protocol: string; transport: string; encryption: string; bytes: number; packets: number; connections: number }>
  ): void {
    if (rows.length === 0) return
    const stmt = this.db.prepare(
      `INSERT INTO protocol_stats (ts, protocol, transport, encryption, bytes, packets, connections)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(ts, protocol) DO UPDATE SET bytes = bytes + excluded.bytes,
                                               packets = packets + excluded.packets,
                                               connections = MAX(connections, excluded.connections)`
    )
    this.db.transaction(() => {
      for (const r of rows) stmt.run([ts, r.protocol, r.transport, r.encryption, r.bytes, r.packets, r.connections])
    })
  }

  /** Traffic series bucketed to `bucketMs` so charts stay small for long ranges. */
  trafficSeries(from: number, to: number, bucketMs: number): TrafficSample[] {
    return this.db
      .prepare(
        `SELECT (ts / ?) * ? AS bucket, SUM(bytes_up) AS up, SUM(bytes_down) AS down, SUM(packets) AS pk
         FROM traffic_stats WHERE ts >= ? AND ts <= ?
         GROUP BY bucket ORDER BY bucket ASC`
      )
      .all<{ bucket: number; up: number; down: number; pk: number }>([bucketMs, bucketMs, from, to])
      .map((r) => ({ ts: Number(r.bucket), bytesUp: Number(r.up), bytesDown: Number(r.down), packets: Number(r.pk) }))
  }

  deviceSeries(deviceId: number, from: number, to: number, bucketMs: number): TrafficSample[] {
    return this.db
      .prepare(
        `SELECT (ts / ?) * ? AS bucket, SUM(bytes_up) AS up, SUM(bytes_down) AS down, SUM(packets) AS pk
         FROM device_stats WHERE device_id = ? AND ts >= ? AND ts <= ?
         GROUP BY bucket ORDER BY bucket ASC`
      )
      .all<{ bucket: number; up: number; down: number; pk: number }>([bucketMs, bucketMs, deviceId, from, to])
      .map((r) => ({ ts: Number(r.bucket), bytesUp: Number(r.up), bytesDown: Number(r.down), packets: Number(r.pk) }))
  }

  protocolTotals(from: number): ProtocolStat[] {
    return this.db
      .prepare(
        `SELECT protocol, transport, encryption, SUM(bytes) AS bytes, SUM(packets) AS packets,
                MAX(connections) AS conns
         FROM protocol_stats WHERE ts >= ? GROUP BY protocol ORDER BY bytes DESC`
      )
      .all<Record<string, SqlValue>>([from])
      .map((r) => ({
        protocol: r.protocol as string,
        transport: r.transport as ProtocolStat['transport'],
        packets: Number(r.packets),
        bytes: Number(r.bytes),
        connections: Number(r.conns),
        encryption: r.encryption as ProtocolStat['encryption']
      }))
  }

  topProtocols(from: number, limit = 8): Array<{ protocol: string; bytes: number }> {
    return this.db
      .prepare(
        `SELECT protocol, SUM(bytes) AS bytes FROM protocol_stats WHERE ts >= ?
         GROUP BY protocol ORDER BY bytes DESC LIMIT ?`
      )
      .all<{ protocol: string; bytes: number }>([from, limit])
      .map((r) => ({ protocol: r.protocol, bytes: Number(r.bytes) }))
  }

  topProtocolsForDevice(deviceIp: string, from: number, limit = 8): Array<{ protocol: string; bytes: number }> {
    return this.db
      .prepare(
        `SELECT app_protocol AS protocol, SUM(bytes_up + bytes_down) AS bytes FROM flows
         WHERE last_seen >= ? AND (device_ip = ? OR src_ip = ? OR dst_ip = ?)
         GROUP BY protocol ORDER BY bytes DESC LIMIT ?`
      )
      .all<{ protocol: string; bytes: number }>([from, deviceIp, deviceIp, deviceIp, limit])
      .map((r) => ({ protocol: r.protocol, bytes: Number(r.bytes) }))
  }

  topTalkers(from: number, limit = 8): Array<{ label: string; ip: string; bytes: number }> {
    return this.db
      .prepare(
        `SELECT d.id, COALESCE(d.label, d.hostname, d.ipv4, d.mac) AS label, COALESCE(d.ipv4, '') AS ip,
                SUM(s.bytes_up + s.bytes_down) AS bytes
         FROM device_stats s JOIN devices d ON d.id = s.device_id
         WHERE s.ts >= ? AND d.ignored = 0
         GROUP BY d.id ORDER BY bytes DESC LIMIT ?`
      )
      .all<{ label: string; ip: string; bytes: number }>([from, limit])
      .map((r) => ({ label: r.label ?? 'unknown', ip: r.ip ?? '', bytes: Number(r.bytes) }))
  }

  /* ---------------------------------------------------------------- */
  /* Alerts                                                            */
  /* ---------------------------------------------------------------- */

  insertAlerts(rows: Array<Omit<AlertRecord, 'id'>>): AlertRecord[] {
    if (rows.length === 0) return []
    const stmt = this.db.prepare(
      `INSERT INTO alerts (ts, kind, severity, title, reason, device_ip, device_mac, acknowledged, details)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`
    )
    const idStmt = this.db.prepare('SELECT last_insert_rowid() AS id')
    const out: AlertRecord[] = []
    this.db.transaction(() => {
      for (const r of rows) {
        stmt.run([r.ts, r.kind, r.severity, r.title, r.reason, r.deviceIp, r.deviceMac, r.details])
        const id = Number(idStmt.get<{ id: number }>()?.id ?? 0)
        out.push({ ...r, id })
      }
    })
    return out
  }

  listAlerts(opts: { limit?: number; offset?: number; onlyUnacked?: boolean }): {
    rows: AlertRecord[]
    total: number
  } {
    const whereSql = opts.onlyUnacked ? 'WHERE acknowledged = 0' : ''
    const total = Number(this.db.prepare(`SELECT COUNT(*) AS n FROM alerts ${whereSql}`).get<{ n: number }>()?.n ?? 0)
    const rows = this.db
      .prepare(`SELECT * FROM alerts ${whereSql} ORDER BY ts DESC LIMIT ? OFFSET ?`)
      .all<Record<string, SqlValue>>([
        Math.min(Math.max(opts.limit ?? 200, 1), 5000),
        Math.max(opts.offset ?? 0, 0)
      ])
      .map(
        (r): AlertRecord => ({
          id: Number(r.id),
          ts: Number(r.ts),
          kind: r.kind as AlertRecord['kind'],
          severity: r.severity as AlertSeverity,
          title: r.title as string,
          reason: r.reason as string,
          deviceIp: (r.device_ip as string) ?? null,
          deviceMac: (r.device_mac as string) ?? null,
          acknowledged: Number(r.acknowledged) === 1,
          details: (r.details as string) ?? null
        })
      )
    return { rows, total }
  }

  ackAlerts(id: number | 'all'): number {
    if (id === 'all') {
      this.db.prepare('UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0').run()
    } else {
      this.db.prepare('UPDATE alerts SET acknowledged = 1 WHERE id = ?').run([id])
    }
    return Number(this.db.prepare('SELECT changes() AS n').get<{ n: number }>()?.n ?? 0)
  }

  /* ---------------------------------------------------------------- */
  /* Logs                                                              */
  /* ---------------------------------------------------------------- */

  insertLog(ts: number, level: LogLevel, scope: string, message: string): number {
    this.db.prepare('INSERT INTO logs (ts, level, scope, message) VALUES (?, ?, ?, ?)').run([ts, level, scope, message])
    return Number(this.db.prepare('SELECT last_insert_rowid() AS id').get<{ id: number }>()?.id ?? 0)
  }

  listLogs(limit = 500, level?: LogLevel): LogEntry[] {
    const where = level ? 'WHERE level = ?' : ''
    const params: SqlValue[] = level ? [level] : []
    return this.db
      .prepare(`SELECT * FROM logs ${where} ORDER BY ts DESC LIMIT ?`)
      .all<Record<string, SqlValue>>([...params, Math.min(Math.max(limit, 1), 10000)])
      .map((r) => ({
        id: Number(r.id),
        ts: Number(r.ts),
        level: r.level as LogLevel,
        scope: r.scope as string,
        message: r.message as string
      }))
  }

  /* ---------------------------------------------------------------- */
  /* Maintenance                                                       */
  /* ---------------------------------------------------------------- */

  applyRetention(policy: RetentionPolicy, now = Date.now()): number {
    const window = RETENTION_MS[policy]
    if (window === null) return 0
    const cutoff = now - window
    let deleted = 0
    const tables: Array<[string, string]> = [
      ['dns_queries', 'ts'],
      ['unencrypted_events', 'ts'],
      ['tls_sessions', 'ts'],
      ['traffic_stats', 'ts'],
      ['device_stats', 'ts'],
      ['protocol_stats', 'ts'],
      ['alerts', 'ts'],
      ['logs', 'ts'],
      ['flows', 'last_seen']
    ]
    this.db.transaction(() => {
      for (const [table, col] of tables) {
        this.db.prepare(`DELETE FROM ${table} WHERE ${col} < ?`).run([cutoff])
        deleted += Number(this.db.prepare('SELECT changes() AS n').get<{ n: number }>()?.n ?? 0)
      }
    })
    return deleted
  }

  purge(scope: 'all' | 'dns' | 'flows' | 'alerts' | 'stats'): number {
    const groups: Record<typeof scope, string[]> = {
      all: [
        'dns_queries',
        'unencrypted_events',
        'tls_sessions',
        'traffic_stats',
        'device_stats',
        'protocol_stats',
        'alerts',
        'flows',
        'devices',
        'logs'
      ],
      dns: ['dns_queries'],
      flows: ['flows', 'unencrypted_events', 'tls_sessions'],
      alerts: ['alerts'],
      stats: ['traffic_stats', 'device_stats', 'protocol_stats']
    }
    let deleted = 0
    this.db.transaction(() => {
      for (const table of groups[scope]) {
        this.db.prepare(`DELETE FROM ${table}`).run()
        deleted += Number(this.db.prepare('SELECT changes() AS n').get<{ n: number }>()?.n ?? 0)
      }
    })
    return deleted
  }

  tableStats(): Array<{ name: string; rows: number }> {
    const tables = this.db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
      .all<{ name: string }>()
    return tables.map((t) => ({
      name: t.name,
      // Table names come from sqlite_master, not from user input.
      rows: Number(this.db.prepare(`SELECT COUNT(*) AS n FROM "${t.name}"`).get<{ n: number }>()?.n ?? 0)
    }))
  }
}

function mapFlow(r: Record<string, SqlValue>): FlowRecord {
  return {
    key: r.key as string,
    srcIp: r.src_ip as string,
    srcPort: Number(r.src_port),
    dstIp: r.dst_ip as string,
    dstPort: Number(r.dst_port),
    transport: r.transport as FlowRecord['transport'],
    appProtocol: r.app_protocol as string,
    protocolConfidence: r.confidence as FlowRecord['protocolConfidence'],
    encryption: r.encryption as FlowRecord['encryption'],
    direction: r.direction as FlowRecord['direction'],
    state: r.state as FlowRecord['state'],
    firstSeen: Number(r.first_seen),
    lastSeen: Number(r.last_seen),
    bytesUp: Number(r.bytes_up),
    bytesDown: Number(r.bytes_down),
    packetsUp: Number(r.packets_up),
    packetsDown: Number(r.packets_down),
    serverName: (r.server_name as string) ?? null,
    remoteHostname: (r.remote_hostname as string) ?? null,
    deviceMac: (r.device_mac as string) ?? null,
    deviceIp: (r.device_ip as string) ?? null
  }
}
