import { useMemo, useState } from 'react'
import type { EncryptionStatus, LiveFlowUpdate, TransportProtocol } from '@shared/types'
import { Badge, Button, Card, DataTable, EncryptionBadge, PageHeader, TextInput, type Column } from '../components/ui'
import { formatBytes, formatTime } from '../format'
import { useApp } from '../state'

const TRANSPORTS: TransportProtocol[] = ['TCP', 'UDP', 'ICMP']

export function LiveTrafficPage(): React.JSX.Element {
  const { t, liveFlows, engine } = useApp()
  const [search, setSearch] = useState('')
  const [transport, setTransport] = useState<TransportProtocol | null>(null)
  const [encryption, setEncryption] = useState<EncryptionStatus | null>(null)
  const [paused, setPaused] = useState(false)
  const [frozen, setFrozen] = useState<LiveFlowUpdate[]>([])

  // Pausing snapshots the current rows so a fast stream can be read.
  const source = paused ? frozen : liveFlows

  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return source.filter((flow) => {
      if (transport && flow.transport !== transport) return false
      if (encryption && flow.encryption !== encryption) return false
      if (!needle) return true
      return [flow.srcIp, flow.dstIp, flow.appProtocol, flow.serverName, String(flow.dstPort)]
        .filter(Boolean)
        .some((field) => String(field).toLowerCase().includes(needle))
    })
  }, [source, search, transport, encryption])

  const columns: Array<Column<LiveFlowUpdate>> = [
    { key: 'ts', header: t('col.time'), width: '90px', render: (f) => <span className="mono text-faint">{formatTime(f.lastSeen)}</span> },
    { key: 'src', header: t('col.source'), render: (f) => <span className="mono">{f.srcIp}<span className="text-faint">:{f.srcPort}</span></span> },
    { key: 'dir', header: '', width: '28px', render: (f) => <span className="text-faint">{f.direction === 'down' ? '←' : '→'}</span> },
    {
      key: 'dst',
      header: t('col.destination'),
      render: (f) => (
        <span className="mono">
          <span className="text-ink">{f.serverName ?? f.dstIp}</span>
          <span className="text-faint">:{f.dstPort}</span>
        </span>
      )
    },
    { key: 'transport', header: t('col.transport'), width: '70px', render: (f) => <span className="text-muted">{f.transport}</span> },
    { key: 'proto', header: t('col.protocol'), width: '110px', render: (f) => <Badge tone={f.encryption === 'unencrypted' ? 'danger' : 'accent'}>{f.appProtocol}</Badge> },
    { key: 'enc', header: t('col.encryption'), width: '120px', render: (f) => <EncryptionBadge value={f.encryption} /> },
    { key: 'state', header: t('col.state'), width: '100px', render: (f) => <span className="text-muted">{f.state}</span> },
    { key: 'delta', header: t('col.size'), align: 'end', width: '90px', render: (f) => <span className="tnum text-accent">{formatBytes(f.deltaBytes, 1)}</span> },
    { key: 'total', header: t('col.bytes'), align: 'end', width: '90px', render: (f) => <span className="tnum">{formatBytes(f.totalBytes, 1)}</span> }
  ]

  return (
    <>
      <PageHeader title={t('nav.live')} description={t('legal.notice')}>
        <TextInput value={search} onChange={setSearch} placeholder={`${t('action.search')}: IP, ${t('col.port')}, ${t('col.protocol')}`} className="w-64" />
        <FilterChips
          options={[{ value: null, label: t('filter.all') }, ...TRANSPORTS.map((p) => ({ value: p, label: p }))]}
          value={transport}
          onChange={setTransport}
        />
        <FilterChips
          options={[
            { value: null, label: t('filter.all') },
            { value: 'encrypted' as const, label: t('filter.encrypted') },
            { value: 'unencrypted' as const, label: t('filter.unencrypted') }
          ]}
          value={encryption}
          onChange={(value) => setEncryption(value as EncryptionStatus | null)}
        />
        <Button
          variant={paused ? 'primary' : 'default'}
          onClick={() => {
            if (!paused) setFrozen(liveFlows)
            setPaused((v) => !v)
          }}
        >
          {paused ? '▶' : '❚❚'}
        </Button>
      </PageHeader>

      <Card className="overflow-hidden">
        <DataTable
          rows={rows}
          columns={columns}
          rowKey={(f) => f.key}
          emptyTitle={engine.state === 'running' ? t('empty.noData') : t('empty.startMonitoring')}
          maxHeight="calc(100vh - 200px)"
        />
      </Card>

      <div className="mt-2 text-xs text-faint">
        {rows.length} / {liveFlows.length} — {t('stat.connections')}
      </div>
    </>
  )
}

function FilterChips<T extends string | null>({
  options,
  value,
  onChange
}: {
  options: Array<{ value: T; label: string }>
  value: T
  onChange: (value: T) => void
}): React.JSX.Element {
  return (
    <div className="flex items-center gap-1 rounded-lg border border-line bg-bg-elevated p-0.5">
      {options.map((option) => (
        <button
          key={String(option.value)}
          onClick={() => onChange(option.value)}
          className={`rounded-md px-2 py-1 text-xs transition-colors ${
            value === option.value ? 'bg-accent-soft font-medium text-accent' : 'text-muted hover:text-ink'
          }`}
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}
