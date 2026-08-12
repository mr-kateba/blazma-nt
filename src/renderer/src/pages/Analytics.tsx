import { useState } from 'react'
import type { TimeRange } from '@shared/types'
import { api, errorMessage } from '../api'
import { PacketsLineChart, TrafficAreaChart } from '../components/charts'
import { Button, Card, PageHeader, RangePicker, Select, StatCard } from '../components/ui'
import { formatBits, formatBytes, formatDateTime, formatNumber } from '../format'
import { useApp, useAsync } from '../state'

export function AnalyticsPage(): React.JSX.Element {
  const { t, settings, notify, engine } = useApp()
  const [range, setRange] = useState<TimeRange>('24h')
  const [format, setFormat] = useState<'csv' | 'json' | 'pdf'>('pdf')

  const { data, loading } = useAsync(() => api.invoke('analytics:report', { range }), [range, engine.state])

  return (
    <>
      <PageHeader title={t('nav.analytics')}>
        <RangePicker value={range} onChange={setRange} ranges={['1h', '24h', '7d', '30d']} />
        <Select
          value={format}
          onChange={setFormat}
          options={[
            { value: 'pdf', label: 'PDF' },
            { value: 'csv', label: 'CSV' },
            { value: 'json', label: 'JSON' }
          ]}
        />
        <Button
          onClick={() =>
            void api
              .invoke('export:run', { dataset: 'traffic', format, range })
              .then((r) => r.path && notify(`${t('action.export')}: ${r.rows}`))
              .catch((err: unknown) => notify(errorMessage(err), 'error'))
          }
        >
          {t('action.export')}
        </Button>
      </PageHeader>

      {!data ? (
        <Card>{loading ? '…' : t('empty.noData')}</Card>
      ) : (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
            <StatCard label="Average bandwidth" value={formatBits(data.avgBandwidthBps)} tone="accent" />
            <StatCard
              label="Peak bandwidth"
              value={formatBits(data.peakBandwidthBps)}
              hint={data.peakAt ? formatDateTime(data.peakAt) : undefined}
            />
            <StatCard label="Average packets/sec" value={formatNumber(data.avgPacketsPerSec, settings.language)} />
            <StatCard label={t('stat.traffic')} value={formatBytes(data.totalBytes)} />
            <StatCard
              label="Upload / Download"
              value={data.upDownRatio > 0 ? data.upDownRatio.toFixed(2) : '—'}
              hint={`${formatBytes(data.bytesUp)} / ${formatBytes(data.bytesDown)}`}
            />
            <StatCard label={t('stat.connections')} value={formatNumber(data.connectionCount, settings.language)} />
          </div>

          <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-3">
            <TopTile label="Top device" value={data.topDevice?.label ?? '—'} bytes={data.topDevice?.bytes ?? 0} />
            <TopTile
              label="Top destination"
              value={data.topDestination?.label ?? '—'}
              bytes={data.topDestination?.bytes ?? 0}
            />
            <TopTile label="Top protocol" value={data.topProtocol?.protocol ?? '—'} bytes={data.topProtocol?.bytes ?? 0} />
          </div>

          <Card title={t('chart.uploadVsDownload')} className="mb-4">
            <TrafficAreaChart data={data.series} emptyLabel={t('empty.noData')} height={260} />
          </Card>

          <Card title={t('chart.packetsPerSecond')}>
            <PacketsLineChart data={data.series} emptyLabel={t('empty.noData')} />
          </Card>
        </>
      )}
    </>
  )
}

function TopTile({ label, value, bytes }: { label: string; value: string; bytes: number }): React.JSX.Element {
  return (
    <div className="rounded-xl border border-line bg-panel px-4 py-3">
      <div className="text-[11px] uppercase tracking-wide text-faint">{label}</div>
      <div className="mono mt-1 truncate text-[15px] text-ink" title={value}>
        {value}
      </div>
      <div className="tnum mt-0.5 text-xs text-muted">{formatBytes(bytes)}</div>
    </div>
  )
}
