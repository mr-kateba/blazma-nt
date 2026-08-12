import { useState } from 'react'
import type { TimeRange } from '@shared/types'
import { HorizontalBars, ProtocolPie, TrafficAreaChart } from '../components/charts'
import { Badge, Card, EmptyState, RangePicker, StatCard } from '../components/ui'
import { formatBytes, formatRate, formatRelative, formatTime } from '../format'
import { api } from '../api'
import { useApp, useAsync } from '../state'
import type { PageId } from '../components/Layout'

export function DashboardPage({ onNavigate }: { onNavigate: (page: PageId) => void }): React.JSX.Element {
  const { t, snapshot, series, alerts, liveFlows, engine, settings } = useApp()
  const [range, setRange] = useState<TimeRange>('15m')

  // Live series covers the running session; longer ranges come from storage.
  const stored = useAsync(() => api.invoke('stats:series', { range }), [range, engine.state])
  const chartData = range === '1m' || range === '5m' || range === '15m' ? series : (stored.data ?? [])

  const totals = snapshot ?? {
    devicesTotal: 0,
    devicesOnline: 0,
    bytesTotal: 0,
    bytesUp: 0,
    bytesDown: 0,
    activeConnections: 0,
    packetsPerSec: 0,
    bytesPerSec: 0,
    topTalkers: [],
    topProtocols: [],
    topDestinations: []
  }

  return (
    <>
      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <StatCard label={t('stat.devices')} value={totals.devicesTotal} />
        <StatCard label={t('stat.online')} value={totals.devicesOnline} tone="ok" />
        <StatCard label={t('stat.traffic')} value={formatBytes(totals.bytesUp + totals.bytesDown)} tone="accent" />
        <StatCard label={t('stat.upload')} value={formatBytes(totals.bytesUp)} />
        <StatCard label={t('stat.download')} value={formatBytes(totals.bytesDown)} />
        <StatCard
          label={t('stat.connections')}
          value={totals.activeConnections}
          hint={engine.state === 'running' ? formatRate(totals.bytesPerSec) : undefined}
        />
      </div>

      <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card
          title={t('chart.trafficOverTime')}
          action={<RangePicker value={range} onChange={setRange} />}
          className="xl:col-span-2"
        >
          <TrafficAreaChart
            data={chartData}
            emptyLabel={engine.state === 'running' ? t('empty.noData') : t('empty.startMonitoring')}
          />
        </Card>

        <Card title={t('panel.topProtocols')}>
          <ProtocolPie
            data={totals.topProtocols.map((p) => ({ label: p.protocol, value: p.bytes }))}
            emptyLabel={t('empty.noData')}
          />
        </Card>
      </div>

      <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title={t('panel.topDevices')}>
          <HorizontalBars
            data={totals.topTalkers.map((d) => ({ label: d.label || d.ip, value: d.bytes }))}
            emptyLabel={t('empty.noData')}
          />
        </Card>
        <Card title={t('panel.topDestinations')}>
          <HorizontalBars
            data={totals.topDestinations.map((d) => ({ label: d.label, value: d.bytes }))}
            emptyLabel={t('empty.noData')}
          />
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card
          title={t('panel.recentAlerts')}
          action={
            <button onClick={() => onNavigate('alerts')} className="text-xs text-accent hover:underline">
              {t('action.details')}
            </button>
          }
        >
          {alerts.length === 0 ? (
            <EmptyState title={t('empty.alerts')} />
          ) : (
            <ul className="space-y-2">
              {alerts.slice(0, 6).map((alert) => (
                <li key={alert.id} className="flex items-start gap-2.5">
                  <SeverityDot severity={alert.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-baseline gap-2">
                      <span className="truncate text-[13px] text-ink">{alert.title}</span>
                      <span className="ms-auto shrink-0 text-[11px] text-faint">
                        {formatRelative(alert.ts, settings.language)}
                      </span>
                    </div>
                    <div className="line-clamp-2 text-xs leading-relaxed text-muted">{alert.reason}</div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card
          title={t('panel.recentConnections')}
          action={
            <button onClick={() => onNavigate('live')} className="text-xs text-accent hover:underline">
              {t('action.details')}
            </button>
          }
        >
          {liveFlows.length === 0 ? (
            <EmptyState title={engine.state === 'running' ? t('empty.noData') : t('empty.startMonitoring')} />
          ) : (
            <ul className="space-y-1">
              {liveFlows.slice(0, 8).map((flow) => (
                <li key={flow.key} className="flex items-center gap-2 text-[12px]">
                  <span className="mono shrink-0 text-faint">{formatTime(flow.lastSeen)}</span>
                  <span className="mono truncate text-muted">{flow.srcIp}</span>
                  <span className="shrink-0 text-faint">→</span>
                  <span className="mono truncate text-ink">{flow.serverName ?? flow.dstIp}</span>
                  <span className="ms-auto flex shrink-0 items-center gap-1.5">
                    <Badge tone={flow.encryption === 'unencrypted' ? 'danger' : 'neutral'}>{flow.appProtocol}</Badge>
                    <span className="tnum text-faint">{formatBytes(flow.totalBytes, 1)}</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  )
}

export function SeverityDot({ severity }: { severity: string }): React.JSX.Element {
  const color =
    severity === 'HIGH'
      ? 'bg-danger'
      : severity === 'MEDIUM'
        ? 'bg-warn'
        : severity === 'LOW'
          ? 'bg-accent'
          : 'bg-faint'
  return <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${color}`} />
}
