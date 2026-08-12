import { useState } from 'react'
import type { DnsQueryRecord } from '@shared/types'
import { api, errorMessage } from '../api'
import { Badge, Button, Card, DataTable, PageHeader, TextInput, type Column } from '../components/ui'
import { formatTime } from '../format'
import { useApp, useAsync } from '../state'

export function DnsPage(): React.JSX.Element {
  const { t, settings, notify, dns: liveDns } = useApp()
  const [search, setSearch] = useState('')
  const [applied, setApplied] = useState('')

  const { data, loading, reload } = useAsync(
    () => api.invoke('dns:list', { text: applied || undefined, limit: 500 }),
    [applied, liveDns.length]
  )

  const rows = data?.rows ?? []

  const columns: Array<Column<DnsQueryRecord>> = [
    { key: 'ts', header: t('col.time'), width: '90px', sortValue: (r) => r.ts, render: (r) => <span className="mono text-faint">{formatTime(r.ts)}</span> },
    { key: 'device', header: t('col.device'), width: '130px', sortValue: (r) => r.deviceIp ?? '', render: (r) => <span className="mono">{r.deviceIp ?? '—'}</span> },
    { key: 'query', header: t('col.query'), sortValue: (r) => r.query, render: (r) => <span className="mono text-ink">{r.query}</span> },
    { key: 'type', header: t('col.type'), width: '70px', render: (r) => <Badge>{r.recordType}</Badge> },
    { key: 'response', header: t('col.response'), render: (r) => <span className="mono truncate text-muted">{r.response ?? '—'}</span> },
    {
      key: 'code',
      header: t('col.status'),
      width: '100px',
      render: (r) => (
        <Badge tone={r.responseCode === 'NOERROR' ? 'ok' : r.responseCode ? 'warn' : 'neutral'}>
          {r.responseCode ?? '—'}
        </Badge>
      )
    },
    { key: 'server', header: t('col.server'), width: '130px', sortValue: (r) => r.server, render: (r) => <span className="mono text-muted">{r.server}</span> },
    { key: 'latency', header: 'ms', align: 'end', width: '60px', sortValue: (r) => r.latencyMs ?? -1, render: (r) => <span className="tnum text-muted">{r.latencyMs ?? '—'}</span> }
  ]

  const clearHistory = (): void => {
    if (!window.confirm(t('dns.clearConfirm'))) return
    void api
      .invoke('dns:clear')
      .then((r) => {
        notify(`${t('dns.clearHistory')}: ${r.deleted}`)
        reload()
      })
      .catch((err: unknown) => notify(errorMessage(err), 'error'))
  }

  return (
    <>
      <PageHeader
        title={t('dns.title')}
        description={settings.privacyMode ? t('settings.privacyModeHelp') : undefined}
      >
        <TextInput value={search} onChange={setSearch} placeholder={`${t('action.search')}: domain, IP`} className="w-64" />
        <Button onClick={() => setApplied(search)}>{t('action.search')}</Button>
        <Button onClick={reload}>⟳</Button>
        <Button
          onClick={() =>
            void api
              .invoke('export:run', { dataset: 'dns', format: 'csv', range: '24h' })
              .then((r) => r.path && notify(`${t('action.export')}: ${r.rows}`))
              .catch((err: unknown) => notify(errorMessage(err), 'error'))
          }
        >
          {t('action.export')}
        </Button>
        <Button variant="danger" onClick={clearHistory}>
          {t('dns.clearHistory')}
        </Button>
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
          emptyTitle={loading ? '…' : t('empty.noData')}
          emptyHint={settings.storeDnsQueries ? t('empty.startMonitoring') : t('settings.storeDns')}
          maxHeight="calc(100vh - 220px)"
        />
      </Card>
    </>
  )
}
