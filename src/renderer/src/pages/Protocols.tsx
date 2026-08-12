import { useState } from 'react'
import type { ProtocolStat, TimeRange } from '@shared/types'
import { api } from '../api'
import { HorizontalBars, ProtocolPie } from '../components/charts'
import { Badge, Card, DataTable, EncryptionBadge, PageHeader, RangePicker, type Column } from '../components/ui'
import { formatBytes, formatNumber } from '../format'
import { useApp, useAsync } from '../state'

export function ProtocolsPage(): React.JSX.Element {
  const { t, settings, engine } = useApp()
  const [range, setRange] = useState<TimeRange>('1h')
  const { data, loading } = useAsync(() => api.invoke('protocols:list', { range }), [range, engine.state])

  const rows = data ?? []
  const unencryptedBytes = rows.filter((r) => r.encryption === 'unencrypted').reduce((sum, r) => sum + r.bytes, 0)
  const totalBytes = rows.reduce((sum, r) => sum + r.bytes, 0)

  const columns: Array<Column<ProtocolStat>> = [
    { key: 'protocol', header: t('col.protocol'), sortValue: (r) => r.protocol, render: (r) => <span className="font-medium text-ink">{r.protocol}</span> },
    { key: 'transport', header: t('col.transport'), sortValue: (r) => r.transport, render: (r) => <Badge>{r.transport}</Badge> },
    { key: 'enc', header: t('col.encryption'), render: (r) => <EncryptionBadge value={r.encryption} /> },
    { key: 'packets', header: t('col.packets'), align: 'end', sortValue: (r) => r.packets, render: (r) => <span className="tnum">{formatNumber(r.packets, settings.language)}</span> },
    { key: 'bytes', header: t('col.bytes'), align: 'end', sortValue: (r) => r.bytes, render: (r) => <span className="tnum">{formatBytes(r.bytes)}</span> },
    { key: 'conns', header: t('col.connections'), align: 'end', sortValue: (r) => r.connections, render: (r) => <span className="tnum">{r.connections}</span> },
    {
      key: 'share',
      header: '%',
      align: 'end',
      sortValue: (r) => r.bytes,
      render: (r) => (
        <span className="tnum text-muted">{totalBytes > 0 ? `${((r.bytes / totalBytes) * 100).toFixed(1)}%` : '—'}</span>
      )
    }
  ]

  return (
    <>
      <PageHeader
        title={t('nav.protocols')}
        description="Protocols are identified from packet headers where possible; a label marked with ? was inferred from the port number alone."
      >
        <RangePicker value={range} onChange={setRange} />
      </PageHeader>

      <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title={t('chart.perProtocol')}>
          <ProtocolPie data={rows.slice(0, 8).map((r) => ({ label: r.protocol, value: r.bytes }))} emptyLabel={t('empty.noData')} />
        </Card>
        <Card
          title={t('filter.unencrypted')}
          action={
            <span className="tnum text-xs text-muted">
              {totalBytes > 0 ? `${((unencryptedBytes / totalBytes) * 100).toFixed(1)}%` : '0%'} · {formatBytes(unencryptedBytes)}
            </span>
          }
        >
          <HorizontalBars
            data={rows
              .filter((r) => r.encryption === 'unencrypted')
              .slice(0, 8)
              .map((r) => ({ label: r.protocol, value: r.bytes }))}
            emptyLabel={t('empty.unencrypted')}
          />
        </Card>
      </div>

      <Card className="overflow-hidden">
        <DataTable
          rows={rows}
          columns={columns}
          rowKey={(r) => r.protocol}
          emptyTitle={loading ? '…' : t('empty.noData')}
          emptyHint={t('empty.startMonitoring')}
          maxHeight="calc(100vh - 520px)"
          initialSort={{ key: 'bytes', dir: 'desc' }}
        />
      </Card>
    </>
  )
}
