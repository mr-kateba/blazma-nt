import { useState } from 'react'
import type { TlsSessionRecord, UnencryptedEvent } from '@shared/types'
import { api } from '../api'
import { Badge, Button, Card, DataTable, PageHeader, TextInput, type Column } from '../components/ui'
import { formatBytes, formatDuration, formatTime } from '../format'
import { useApp, useAsync } from '../state'

export function UnencryptedPage(): React.JSX.Element {
  const { t, settings, unencrypted: live } = useApp()
  const [search, setSearch] = useState('')
  const [applied, setApplied] = useState('')

  const { data, loading, reload } = useAsync(
    () => api.invoke('unencrypted:list', { text: applied || undefined, limit: 500 }),
    [applied, live.length]
  )
  const rows = data?.rows ?? []

  const columns: Array<Column<UnencryptedEvent>> = [
    { key: 'ts', header: t('col.time'), width: '90px', sortValue: (r) => r.ts, render: (r) => <span className="mono text-faint">{formatTime(r.ts)}</span> },
    { key: 'device', header: t('col.device'), width: '130px', sortValue: (r) => r.deviceIp ?? '', render: (r) => <span className="mono">{r.deviceIp ?? '—'}</span> },
    { key: 'src', header: t('col.source'), width: '160px', render: (r) => <span className="mono text-muted">{r.srcIp}:{r.srcPort}</span> },
    { key: 'dst', header: t('col.destination'), width: '170px', render: (r) => <span className="mono">{r.dstIp}:{r.dstPort}</span> },
    { key: 'proto', header: t('col.protocol'), width: '90px', sortValue: (r) => r.protocol, render: (r) => <Badge tone="danger">{r.protocol}</Badge> },
    { key: 'bytes', header: t('col.size'), align: 'end', width: '80px', sortValue: (r) => r.bytes, render: (r) => <span className="tnum">{formatBytes(r.bytes, 1)}</span> },
    {
      key: 'meta',
      header: t('col.metadata'),
      render: (r) => (
        <div className="flex items-center gap-2">
          <span className="mono truncate text-muted" title={r.metadata}>
            {r.metadata}
          </span>
          {r.redacted && <Badge tone="violet">{t('unenc.redacted')}</Badge>}
        </div>
      )
    }
  ]

  return (
    <>
      <PageHeader title={t('unenc.title')} description={t('unenc.explain')}>
        <TextInput value={search} onChange={setSearch} placeholder={t('action.search')} className="w-56" />
        <Button onClick={() => setApplied(search)}>{t('action.search')}</Button>
        <Button onClick={reload}>⟳</Button>
      </PageHeader>

      {settings.privacyMode && (
        <div className="mb-3 rounded-lg border border-line bg-panel px-4 py-2.5 text-xs text-muted">
          {t('engine.privacyOn')} — {t('settings.privacyModeHelp')}
        </div>
      )}

      <Card className="overflow-hidden">
        <DataTable
          rows={rows}
          columns={columns}
          rowKey={(r) => String(r.id)}
          emptyTitle={loading ? '…' : t('empty.unencrypted')}
          emptyHint={t('empty.startMonitoring')}
          maxHeight="calc(100vh - 240px)"
        />
      </Card>
    </>
  )
}

export function TlsPage(): React.JSX.Element {
  const { t, tls: live } = useApp()
  const [search, setSearch] = useState('')
  const [applied, setApplied] = useState('')

  const { data, loading, reload } = useAsync(
    () => api.invoke('tls:list', { text: applied || undefined, limit: 500 }),
    [applied, live.length]
  )
  const rows = data ?? []

  const columns: Array<Column<TlsSessionRecord>> = [
    { key: 'ts', header: t('col.time'), width: '90px', sortValue: (r) => r.ts, render: (r) => <span className="mono text-faint">{formatTime(r.ts)}</span> },
    { key: 'device', header: t('col.device'), width: '130px', render: (r) => <span className="mono">{r.deviceIp ?? '—'}</span> },
    {
      key: 'sni',
      header: t('col.sni'),
      sortValue: (r) => r.sni ?? '',
      render: (r) => <span className="mono text-ink">{r.sni ?? <span className="text-faint">—</span>}</span>
    },
    { key: 'server', header: t('col.destination'), width: '170px', render: (r) => <span className="mono text-muted">{r.serverIp}:{r.serverPort}</span> },
    { key: 'version', header: t('col.version'), width: '90px', render: (r) => (r.version ? <Badge tone="ok">{r.version}</Badge> : <Badge>TLS</Badge>) },
    { key: 'issuer', header: t('col.issuer'), render: (r) => <span className="truncate text-muted">{r.certIssuer ?? '—'}</span> },
    { key: 'subject', header: t('col.subject'), render: (r) => <span className="truncate text-muted">{r.certSubject ?? '—'}</span> },
    { key: 'bytes', header: t('col.size'), align: 'end', width: '80px', sortValue: (r) => r.bytes, render: (r) => <span className="tnum">{formatBytes(r.bytes, 1)}</span> },
    { key: 'dur', header: t('col.duration'), align: 'end', width: '80px', sortValue: (r) => r.durationMs, render: (r) => <span className="tnum text-muted">{formatDuration(r.durationMs)}</span> }
  ]

  return (
    <>
      <PageHeader title={t('tls.title')} description={t('tls.explain')}>
        <TextInput value={search} onChange={setSearch} placeholder={`${t('action.search')}: ${t('col.sni')}`} className="w-56" />
        <Button onClick={() => setApplied(search)}>{t('action.search')}</Button>
        <Button onClick={reload}>⟳</Button>
      </PageHeader>

      <Card className="overflow-hidden">
        <DataTable
          rows={rows}
          columns={columns}
          rowKey={(r) => String(r.id)}
          emptyTitle={loading ? '…' : t('empty.noData')}
          emptyHint={t('empty.startMonitoring')}
          maxHeight="calc(100vh - 220px)"
        />
      </Card>
    </>
  )
}
