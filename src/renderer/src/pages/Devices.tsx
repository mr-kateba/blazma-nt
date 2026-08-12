import { useMemo, useState } from 'react'
import type { DeviceRecord, TimeRange } from '@shared/types'
import { api, errorMessage } from '../api'
import { HorizontalBars, TrafficAreaChart } from '../components/charts'
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  PageHeader,
  RangePicker,
  TextInput,
  type Column
} from '../components/ui'
import { formatBytes, formatDateTime, formatRelative } from '../format'
import { useApp, useAsync } from '../state'

export function DevicesPage(): React.JSX.Element {
  const { t, devices, settings, notify } = useApp()
  const [search, setSearch] = useState('')
  const [showIgnored, setShowIgnored] = useState(false)
  const [selected, setSelected] = useState<number | null>(null)

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return devices
      .filter((d) => showIgnored || !d.ignored)
      .filter((d) =>
        needle.length === 0
          ? true
          : [d.label, d.hostname, d.ipv4, d.ipv6, d.mac, d.vendor]
              .filter(Boolean)
              .some((field) => String(field).toLowerCase().includes(needle))
      )
  }, [devices, search, showIgnored])

  const columns: Array<Column<DeviceRecord>> = [
    {
      key: 'name',
      header: t('col.device'),
      sortValue: (d) => d.label ?? d.hostname ?? d.ipv4 ?? d.mac ?? '',
      render: (d) => (
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 shrink-0 rounded-full ${d.online ? 'bg-ok' : 'bg-faint'}`} />
          <span className="truncate font-medium text-ink">{d.label ?? d.hostname ?? d.ipv4 ?? d.mac ?? '—'}</span>
          {d.paused && <Badge tone="warn">paused</Badge>}
          {d.ignored && <Badge tone="neutral">ignored</Badge>}
        </div>
      )
    },
    { key: 'ipv4', header: t('col.ipv4'), sortValue: (d) => d.ipv4 ?? '', render: (d) => <span className="mono">{d.ipv4 ?? '—'}</span> },
    { key: 'mac', header: t('col.mac'), sortValue: (d) => d.mac ?? '', render: (d) => <span className="mono text-muted">{d.mac ?? '—'}</span> },
    { key: 'vendor', header: t('col.vendor'), sortValue: (d) => d.vendor ?? '', render: (d) => <span className="text-muted">{d.vendor ?? '—'}</span> },
    {
      key: 'status',
      header: t('col.status'),
      sortValue: (d) => (d.online ? 1 : 0),
      render: (d) => <Badge tone={d.online ? 'ok' : 'neutral'}>{d.online ? t('value.online') : t('value.offline')}</Badge>
    },
    { key: 'up', header: t('col.upload'), align: 'end', sortValue: (d) => d.bytesUp, render: (d) => <span className="tnum">{formatBytes(d.bytesUp)}</span> },
    { key: 'down', header: t('col.download'), align: 'end', sortValue: (d) => d.bytesDown, render: (d) => <span className="tnum">{formatBytes(d.bytesDown)}</span> },
    { key: 'conns', header: t('col.connections'), align: 'end', sortValue: (d) => d.connections, render: (d) => <span className="tnum">{d.connections}</span> },
    {
      key: 'lastSeen',
      header: t('col.lastSeen'),
      align: 'end',
      sortValue: (d) => d.lastSeen,
      render: (d) => <span className="text-muted">{formatRelative(d.lastSeen, settings.language)}</span>
    }
  ]

  if (selected !== null) {
    return <DeviceDetail id={selected} onBack={() => setSelected(null)} />
  }

  return (
    <>
      <PageHeader title={t('nav.devices')}>
        <TextInput value={search} onChange={setSearch} placeholder={`${t('action.search')}: IP, MAC, ${t('col.vendor')}`} className="w-64" />
        <Button variant={showIgnored ? 'primary' : 'default'} onClick={() => setShowIgnored((v) => !v)}>
          {showIgnored ? t('action.unignoreDevice') : t('action.ignoreDevice')}
        </Button>
        <Button
          onClick={() =>
            void api
              .invoke('export:run', { dataset: 'devices', format: 'csv', range: '24h' })
              .then((r) => r.path && notify(`${t('action.export')}: ${r.rows}`))
              .catch((err: unknown) => notify(errorMessage(err), 'error'))
          }
        >
          {t('action.export')} CSV
        </Button>
      </PageHeader>

      <Card className="overflow-hidden">
        <DataTable
          rows={filtered}
          columns={columns}
          rowKey={(d) => String(d.id)}
          onRowClick={(d) => setSelected(d.id)}
          emptyTitle={devices.length === 0 ? t('empty.noData') : t('empty.noResults')}
          emptyHint={devices.length === 0 ? t('empty.startMonitoring') : undefined}
          maxHeight="calc(100vh - 220px)"
          initialSort={{ key: 'down', dir: 'desc' }}
        />
      </Card>
    </>
  )
}

function DeviceDetail({ id, onBack }: { id: number; onBack: () => void }): React.JSX.Element {
  const { t, settings, notify } = useApp()
  const [range, setRange] = useState<TimeRange>('1h')
  const { data, loading, reload } = useAsync(() => api.invoke('devices:detail', { id, range }), [id, range])

  if (loading && !data) return <EmptyState title="…" />
  if (!data) return <EmptyState title={t('empty.noData')} />

  const { device, series, topDestinations, topProtocols, flows, dns } = data

  const setFlag = (patch: { paused?: boolean; ignored?: boolean }): void => {
    void api
      .invoke('devices:setFlags', { id, ...patch })
      .then(() => reload())
      .catch((err: unknown) => notify(errorMessage(err), 'error'))
  }

  return (
    <>
      <PageHeader
        title={device.label ?? device.hostname ?? device.ipv4 ?? device.mac ?? t('col.device')}
        description={`${device.vendor ?? ''} ${device.mac ?? ''}`.trim()}
      >
        <RangePicker value={range} onChange={setRange} />
        <Button onClick={() => setFlag({ paused: !device.paused })}>
          {device.paused ? t('action.resumeDevice') : t('action.pauseDevice')}
        </Button>
        <Button onClick={() => setFlag({ ignored: !device.ignored })}>
          {device.ignored ? t('action.unignoreDevice') : t('action.ignoreDevice')}
        </Button>
        <Button variant="ghost" onClick={onBack}>
          ← {t('action.back')}
        </Button>
      </PageHeader>

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <InfoTile label={t('col.status')} value={device.online ? t('value.online') : t('value.offline')} />
        <InfoTile label={t('col.upload')} value={formatBytes(device.bytesUp)} />
        <InfoTile label={t('col.download')} value={formatBytes(device.bytesDown)} />
        <InfoTile label={t('col.packets')} value={String(device.packetsUp + device.packetsDown)} />
        <InfoTile label={t('col.firstSeen')} value={formatDateTime(device.firstSeen)} />
        <InfoTile label={t('col.lastSeen')} value={formatRelative(device.lastSeen, settings.language)} />
      </div>

      <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title={t('chart.trafficOverTime')} className="xl:col-span-2">
          <TrafficAreaChart data={series} emptyLabel={t('empty.noData')} height={220} />
        </Card>
        <Card title={t('panel.topProtocols')}>
          <HorizontalBars
            data={topProtocols.map((p) => ({ label: p.protocol, value: p.bytes }))}
            emptyLabel={t('empty.noData')}
          />
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title={t('panel.topDestinations')}>
          <DataTable
            rows={topDestinations}
            columns={[
              { key: 'label', header: t('col.destination'), render: (r) => <span className="mono truncate">{r.label}</span> },
              { key: 'bytes', header: t('col.bytes'), align: 'end', render: (r) => <span className="tnum">{formatBytes(r.bytes)}</span> },
              { key: 'conns', header: t('col.connections'), align: 'end', render: (r) => <span className="tnum">{r.connections}</span> }
            ]}
            rowKey={(r) => r.label}
            emptyTitle={t('empty.noData')}
            maxHeight="280px"
          />
        </Card>

        <Card title={t('nav.dns')}>
          <DataTable
            rows={dns}
            columns={[
              { key: 'query', header: t('col.query'), render: (r) => <span className="mono truncate">{r.query}</span> },
              { key: 'type', header: t('col.type'), render: (r) => <Badge>{r.recordType}</Badge> },
              { key: 'response', header: t('col.response'), render: (r) => <span className="mono truncate text-muted">{r.response ?? '—'}</span> }
            ]}
            rowKey={(r) => String(r.id)}
            emptyTitle={settings.privacyMode ? t('engine.privacyOn') : t('empty.noData')}
            maxHeight="280px"
          />
        </Card>
      </div>

      <Card title={t('nav.connections')} className="mt-4">
        <DataTable
          rows={flows}
          columns={[
            { key: 'dst', header: t('col.destination'), render: (f) => <span className="mono truncate">{f.serverName ?? f.remoteHostname ?? f.dstIp}:{f.dstPort}</span> },
            { key: 'proto', header: t('col.protocol'), render: (f) => <Badge tone={f.encryption === 'unencrypted' ? 'danger' : 'neutral'}>{f.appProtocol}</Badge> },
            { key: 'state', header: t('col.state'), render: (f) => <span className="text-muted">{f.state}</span> },
            { key: 'up', header: t('col.upload'), align: 'end', render: (f) => <span className="tnum">{formatBytes(f.bytesUp)}</span> },
            { key: 'down', header: t('col.download'), align: 'end', render: (f) => <span className="tnum">{formatBytes(f.bytesDown)}</span> }
          ]}
          rowKey={(f) => f.key}
          emptyTitle={t('empty.noData')}
          maxHeight="340px"
        />
      </Card>
    </>
  )
}

function InfoTile({ label, value }: { label: string; value: string }): React.JSX.Element {
  return (
    <div className="rounded-lg border border-line bg-panel px-3 py-2">
      <div className="text-[10px] uppercase tracking-wide text-faint">{label}</div>
      <div className="tnum mt-0.5 truncate text-sm text-ink">{value}</div>
    </div>
  )
}
