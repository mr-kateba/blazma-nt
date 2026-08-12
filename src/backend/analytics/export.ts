import { writeFileSync } from 'node:fs'
import type { ExportDataset, ExportFormat } from '../../shared/ipc.js'
import type { TimeRange } from '../../shared/types.js'
import type { Store } from '../database/store.js'
import { formatBytes } from '../utils/bytes.js'
import { renderTablePdf } from '../utils/pdf.js'
import { resolveRange } from './ranges.js'

interface Dataset {
  columns: string[]
  rows: string[][]
  raw: unknown[]
}

/** RFC 4180 quoting, plus a guard against spreadsheet formula injection. */
function csvCell(value: string): string {
  const text = value ?? ''
  const dangerous = /^[=+\-@\t\r]/.test(text)
  const safe = dangerous ? `'${text}` : text
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe
}

function toCsv(dataset: Dataset): string {
  const lines = [dataset.columns.map(csvCell).join(',')]
  for (const row of dataset.rows) lines.push(row.map(csvCell).join(','))
  return `﻿${lines.join('\r\n')}\r\n`
}

const iso = (ts: number): string => new Date(ts).toISOString().replace('T', ' ').slice(0, 19)

function collect(store: Store, dataset: ExportDataset, range: TimeRange): Dataset {
  const { from, to, bucketMs } = resolveRange(range)

  switch (dataset) {
    case 'devices': {
      const rows = store.listDevices(true, Date.now() - 120_000)
      return {
        columns: ['Name', 'IPv4', 'MAC', 'Vendor', 'Status', 'Upload', 'Download', 'Connections', 'First seen', 'Last seen'],
        rows: rows.map((d) => [
          d.label ?? d.hostname ?? '—',
          d.ipv4 ?? '—',
          d.mac ?? '—',
          d.vendor ?? '—',
          d.online ? 'Online' : 'Offline',
          formatBytes(d.bytesUp),
          formatBytes(d.bytesDown),
          String(d.connections),
          iso(d.firstSeen),
          iso(d.lastSeen)
        ]),
        raw: rows
      }
    }
    case 'connections': {
      const { rows } = store.queryFlows({ from, to, limit: 5000, sortBy: 'bytes' })
      return {
        columns: ['Last seen', 'Source', 'Destination', 'Protocol', 'Transport', 'Encryption', 'State', 'Upload', 'Download'],
        rows: rows.map((f) => [
          iso(f.lastSeen),
          `${f.srcIp}:${f.srcPort}`,
          `${f.serverName ?? f.remoteHostname ?? f.dstIp}:${f.dstPort}`,
          f.appProtocol,
          f.transport,
          f.encryption,
          f.state,
          formatBytes(f.bytesUp),
          formatBytes(f.bytesDown)
        ]),
        raw: rows
      }
    }
    case 'traffic': {
      const rows = store.trafficSeries(from, to, bucketMs)
      return {
        columns: ['Time', 'Upload', 'Download', 'Total', 'Packets'],
        rows: rows.map((s) => [
          iso(s.ts),
          formatBytes(s.bytesUp),
          formatBytes(s.bytesDown),
          formatBytes(s.bytesUp + s.bytesDown),
          String(s.packets)
        ]),
        raw: rows
      }
    }
    case 'alerts': {
      const { rows } = store.listAlerts({ limit: 5000 })
      return {
        columns: ['Time', 'Severity', 'Type', 'Title', 'Device', 'Reason'],
        rows: rows.map((a) => [
          iso(a.ts),
          a.severity,
          a.kind,
          a.title,
          a.deviceIp ?? a.deviceMac ?? '—',
          a.reason
        ]),
        raw: rows
      }
    }
    case 'dns': {
      const { rows } = store.listDns({ limit: 5000 })
      return {
        columns: ['Time', 'Device', 'Server', 'Query', 'Type', 'Response', 'Result'],
        rows: rows.map((d) => [
          iso(d.ts),
          d.deviceIp ?? '—',
          d.server,
          d.query,
          d.recordType,
          d.response ?? '—',
          d.responseCode ?? '—'
        ]),
        raw: rows
      }
    }
  }
}

export function runExport(
  store: Store,
  dataset: ExportDataset,
  format: ExportFormat,
  range: TimeRange,
  outputPath: string
): number {
  const data = collect(store, dataset, range)

  if (format === 'csv') {
    writeFileSync(outputPath, toCsv(data), 'utf8')
  } else if (format === 'json') {
    writeFileSync(
      outputPath,
      JSON.stringify({ dataset, range, exportedAt: new Date().toISOString(), rows: data.raw }, null, 2),
      'utf8'
    )
  } else {
    writeFileSync(
      outputPath,
      renderTablePdf({
        title: `blazma.nt — ${dataset}`,
        subtitle: `range: ${range}   exported: ${iso(Date.now())}   rows: ${data.rows.length}`,
        columns: data.columns,
        rows: data.rows
      })
    )
  }

  return data.rows.length
}
