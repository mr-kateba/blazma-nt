import type { SqliteDb } from './driver.js'

/**
 * Ordered, append-only migrations. Never edit a shipped migration — add a new
 * one. `user_version` tracks which have been applied.
 */
export const MIGRATIONS: Array<{ version: number; name: string; sql: string }> = [
  {
    version: 1,
    name: 'initial-schema',
    sql: `
      CREATE TABLE interfaces (
        id            TEXT PRIMARY KEY,
        name          TEXT NOT NULL,
        description   TEXT,
        mac           TEXT,
        ipv4          TEXT,
        ipv6          TEXT,
        gateway       TEXT,
        prefix_length INTEGER,
        last_used     INTEGER
      );

      CREATE TABLE devices (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        mac         TEXT UNIQUE,
        ipv4        TEXT,
        ipv6        TEXT,
        hostname    TEXT,
        vendor      TEXT,
        label       TEXT,
        first_seen  INTEGER NOT NULL,
        last_seen   INTEGER NOT NULL,
        bytes_up    INTEGER NOT NULL DEFAULT 0,
        bytes_down  INTEGER NOT NULL DEFAULT 0,
        packets_up  INTEGER NOT NULL DEFAULT 0,
        packets_down INTEGER NOT NULL DEFAULT 0,
        is_local    INTEGER NOT NULL DEFAULT 1,
        paused      INTEGER NOT NULL DEFAULT 0,
        ignored     INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX idx_devices_ipv4 ON devices(ipv4);
      CREATE INDEX idx_devices_last_seen ON devices(last_seen);

      CREATE TABLE flows (
        key         TEXT PRIMARY KEY,
        src_ip      TEXT NOT NULL,
        src_port    INTEGER NOT NULL,
        dst_ip      TEXT NOT NULL,
        dst_port    INTEGER NOT NULL,
        transport   TEXT NOT NULL,
        app_protocol TEXT NOT NULL,
        confidence  TEXT NOT NULL,
        encryption  TEXT NOT NULL,
        direction   TEXT NOT NULL,
        state       TEXT NOT NULL,
        first_seen  INTEGER NOT NULL,
        last_seen   INTEGER NOT NULL,
        bytes_up    INTEGER NOT NULL DEFAULT 0,
        bytes_down  INTEGER NOT NULL DEFAULT 0,
        packets_up  INTEGER NOT NULL DEFAULT 0,
        packets_down INTEGER NOT NULL DEFAULT 0,
        server_name TEXT,
        remote_hostname TEXT,
        device_mac  TEXT,
        device_ip   TEXT
      );
      CREATE INDEX idx_flows_last_seen ON flows(last_seen);
      CREATE INDEX idx_flows_device_ip ON flows(device_ip);
      CREATE INDEX idx_flows_protocol ON flows(app_protocol);
      CREATE INDEX idx_flows_dst ON flows(dst_ip);

      CREATE TABLE dns_queries (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          INTEGER NOT NULL,
        device_ip   TEXT,
        device_mac  TEXT,
        server      TEXT NOT NULL,
        query       TEXT NOT NULL,
        record_type TEXT NOT NULL,
        response    TEXT,
        response_code TEXT,
        latency_ms  INTEGER
      );
      CREATE INDEX idx_dns_ts ON dns_queries(ts);
      CREATE INDEX idx_dns_query ON dns_queries(query);
      CREATE INDEX idx_dns_device ON dns_queries(device_ip);

      CREATE TABLE unencrypted_events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          INTEGER NOT NULL,
        device_ip   TEXT,
        device_mac  TEXT,
        src_ip      TEXT NOT NULL,
        src_port    INTEGER NOT NULL,
        dst_ip      TEXT NOT NULL,
        dst_port    INTEGER NOT NULL,
        protocol    TEXT NOT NULL,
        bytes       INTEGER NOT NULL DEFAULT 0,
        metadata    TEXT NOT NULL,
        redacted    INTEGER NOT NULL DEFAULT 1
      );
      CREATE INDEX idx_unenc_ts ON unencrypted_events(ts);

      CREATE TABLE tls_sessions (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          INTEGER NOT NULL,
        device_ip   TEXT,
        server_ip   TEXT NOT NULL,
        server_port INTEGER NOT NULL,
        sni         TEXT,
        version     TEXT,
        cert_subject TEXT,
        cert_issuer TEXT,
        bytes       INTEGER NOT NULL DEFAULT 0,
        duration_ms INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX idx_tls_ts ON tls_sessions(ts);
      CREATE INDEX idx_tls_sni ON tls_sessions(sni);

      CREATE TABLE traffic_stats (
        ts          INTEGER PRIMARY KEY,
        bytes_up    INTEGER NOT NULL DEFAULT 0,
        bytes_down  INTEGER NOT NULL DEFAULT 0,
        packets     INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE device_stats (
        ts          INTEGER NOT NULL,
        device_id   INTEGER NOT NULL,
        bytes_up    INTEGER NOT NULL DEFAULT 0,
        bytes_down  INTEGER NOT NULL DEFAULT 0,
        packets     INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (ts, device_id)
      );

      CREATE TABLE protocol_stats (
        ts          INTEGER NOT NULL,
        protocol    TEXT NOT NULL,
        transport   TEXT NOT NULL,
        encryption  TEXT NOT NULL,
        bytes       INTEGER NOT NULL DEFAULT 0,
        packets     INTEGER NOT NULL DEFAULT 0,
        connections INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (ts, protocol)
      );

      CREATE TABLE alerts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          INTEGER NOT NULL,
        kind        TEXT NOT NULL,
        severity    TEXT NOT NULL,
        title       TEXT NOT NULL,
        reason      TEXT NOT NULL,
        device_ip   TEXT,
        device_mac  TEXT,
        acknowledged INTEGER NOT NULL DEFAULT 0,
        details     TEXT
      );
      CREATE INDEX idx_alerts_ts ON alerts(ts);

      CREATE TABLE settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE logs (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        ts      INTEGER NOT NULL,
        level   TEXT NOT NULL,
        scope   TEXT NOT NULL,
        message TEXT NOT NULL
      );
      CREATE INDEX idx_logs_ts ON logs(ts);
    `
  }
]

export function runMigrations(db: SqliteDb): { from: number; to: number } {
  const row = db.prepare('PRAGMA user_version').get<{ user_version: number }>()
  const current = Number(row?.user_version ?? 0)
  let applied = current

  for (const migration of MIGRATIONS) {
    if (migration.version <= current) continue
    db.transaction(() => {
      db.exec(migration.sql)
      // user_version does not accept bound parameters; version is an integer
      // literal from this file, never user input.
      db.exec(`PRAGMA user_version = ${migration.version}`)
    })
    applied = migration.version
  }

  return { from: current, to: applied }
}
