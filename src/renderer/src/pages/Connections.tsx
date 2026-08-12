import { useState } from 'react'
import type { FlowRecord, TimeRange } from '@shared/types'
import { api, errorMessage } from '../api'
import {
  Badge,
  Button,
  Card,
  DataTable,
  EncryptionBadge,
  PageHeader,
  RangePicker,
  Select,
  TextInput,
  type Column
} from '../components/ui'
import { formatBytes, formatDuration, formatTime } from '../format'
import { useApp, useAsync } from '../state'
import { resolveRangeMs } from '../ranges'

const PAGE_SIZE = 200

export function ConnectionsPage(): React.JSX.Element {
  const { t, notify } = useApp()
  const [search, setSearch] = useState('')
  const [applied, setApplied] = useState('')
  const [range, setRange] = useState<TimeRange>('1h')
  const [encryption, setEncryption] = useState<'all' | 'encrypted' | 'unencrypted'>('all')
  const [transport, setTransport] = useState<'all' | 'TCP' | 'UDP'>('all')
  const [page, setPage] = useState(0)

  const { data, loading, reload } = useAsync(
    () =>
      api.invoke('flows:query', {
        text: applied || undefined,
        from: Date.now() - resolveRangeMs(range),
        encryption: encryption === 'all' ? undefined : [encryption],
        transport: transport === 'all' ? undefined : [transport],
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
        sortBy: 'lastSeen',
        sortDir: 'desc'
      }),
    [applied, range, encryption, transport, page]
  )

  const rows = data?.rows ?? []
  const total = data?.total ?? 0

  const columns: Array<Column<FlowRecord>> = [
    { key: 'ts', header: t('col.time'), width: '90px', sortValue: (f) => f.lastSeen, render: (f) => <span className="mono text-faint">{formatTime(f.lastSeen)}</span> },
    { key: 'src', header: t('col.source'), sortValue: (f) => f.srcIp, render: (f) => <span className="mono">{f.srcIp}<span className="text-faint">:{f.srcPort}</span></span> },
    {
      key: 'dst',
      header: t('col.destination'),
      sortValue: (f) => f.serverName ?? f.dstIp,
      render: (f) => (
        <span className="mono">
          <span className="text-ink">{f.serverName ?? f.remoteHostname ?? f.dstIp}</span>
          <span className="text-faint">:{f.dstPort}</span>
        </span>
      )
    },
    {
      key: 'proto',
      header: t('col.protocol'),
      width: '130px',
      sortValue: (f) => f.appProtocol,
      render: (f) => (
        <Badge tone={f.encryption === 'unencrypted' ? 'danger' : 'accent'} title={`confidence: ${f.protocolConfidence}`}>
          {f.appProtocol}
          {f.protocolConfidence === 'port-hint' && <span className="opacity-60">?</span>}
        </Badge>
      )
    },
    { key: 'enc', header: t('col.encryption'), width: '120px', render: (f) => <EncryptionBadge value={f.encryption} /> },
    { key: 'state', header: t('col.state'), width: '100px', sortValue: (f) => f.state, render: (f) => <span className="text-muted">{f.state}</span> },
    { key: 'dur', header: t('col.duration'), align: 'end', width: '80px', sortValue: (f) => f.lastSeen - f.firstSeen, render: (f) => <span className="tnum text-muted">{formatDuration(f.lastSeen - f.firstSeen)}</span> },
    { key: 'up', header: t('col.upload'), align: 'end', width: '90px', sortValue: (f) => f.bytesUp, render: (f) => <span className="tnum">{formatBytes(f.bytesUp, 1)}</span> },
    { key: 'down', header: t('col.download'), align: 'end', width: '90px', sortValue: (f) => f.bytesDown, render: (f) => <span className="tnum">{formatBytes(f.bytesDown, 1)}</span> }
  ]

  return (
    <>
      <PageHeader title={t('nav.connections')}>
        <TextInput
          value={search}
          onChange={setSearch}
          placeholder={`${t('action.search')}: IP, domain, ${t('col.protocol')}`}
          className="w-64"
        />
        <Button
          onClick={() => {
            setPage(0)
            setApplied(search)
          }}
        >
          {t('action.search')}
        </Button>
        <RangePicker value={range} onChange={(value) => { setPage(0); setRange(value) }} />
        <Select
          value={transport}
          onChange={(value) => { setPage(0); setTransport(value) }}
          options={[
            { value: 'all', label: `${t('col.transport')}: ${t('filter.all')}` },
            { value: 'TCP', label: 'TCP' },
            { value: 'UDP', label: 'UDP' }
          ]}
        />
        <Select
          value={encryption}
          onChange={(value) => { setPage(0); setEncryption(value) }}
          options={[
            { value: 'all', label: `${t('col.encryption')}: ${t('filter.all')}` },
            { value: 'encrypted', label: t('filter.encrypted') },
            { value: 'unencrypted', label: t('filter.unencrypted') }
          ]}
        />
        <Button onClick={reload}>⟳</Button>
        <Button
          onClick={() =>
            void api
              .invoke('export:run', { dataset: 'connections', format: 'csv', range })
              .then((r) => r.path && notify(`${t('action.export')}: ${r.rows}`))
              .catch((err: unknown) => notify(errorMessage(err), 'error'))
          }
        >
          {t('action.export')}
        </Button>
      </PageHeader>

      <Card className="overflow-hidden">
        <DataTable
          rows={rows}
          columns={columns}
          rowKey={(f) => f.key}
          emptyTitle={loading ? '…' : total === 0 ? t('empty.noData') : t('empty.noResults')}
          maxHeight="calc(100vh - 240px)"
        />
      </Card>

      <div className="mt-3 flex items-center justify-between text-xs text-muted">
        <span className="tnum">
          {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} / {total}
        </span>
        <div className="flex gap-2">
          <Button disabled={page === 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>
            ‹
          </Button>
          <Button disabled={(page + 1) * PAGE_SIZE >= total} onClick={() => setPage((p) => p + 1)}>
            ›
          </Button>
        </div>
      </div>
    </>
  )
}
