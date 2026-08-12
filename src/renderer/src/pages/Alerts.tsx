import { useState } from 'react'
import type { AlertRecord } from '@shared/types'
import { api, errorMessage } from '../api'
import { Badge, Button, Card, EmptyState, PageHeader } from '../components/ui'
import { formatDateTime, formatRelative } from '../format'
import { useApp, useAsync } from '../state'

export function AlertsPage(): React.JSX.Element {
  const { t, settings, notify, alerts: live } = useApp()
  const [onlyUnacked, setOnlyUnacked] = useState(false)

  const { data, loading, reload } = useAsync(
    () => api.invoke('alerts:list', { limit: 300, onlyUnacked }),
    [onlyUnacked, live.length]
  )
  const rows = data?.rows ?? []

  const act = (promise: Promise<unknown>): void => {
    void promise.then(() => reload()).catch((err: unknown) => notify(errorMessage(err), 'error'))
  }

  return (
    <>
      <PageHeader
        title={t('nav.alerts')}
        description="Alerts describe what was measured and why it stood out. None of them assert that traffic is malicious."
      >
        <Button variant={onlyUnacked ? 'primary' : 'default'} onClick={() => setOnlyUnacked((v) => !v)}>
          {onlyUnacked ? t('filter.all') : t('action.acknowledge')}
        </Button>
        <Button onClick={() => act(api.invoke('alerts:ack', { id: 'all' }))}>{t('action.acknowledgeAll')}</Button>
        <Button
          onClick={() =>
            void api
              .invoke('export:run', { dataset: 'alerts', format: 'csv', range: '30d' })
              .then((r) => r.path && notify(`${t('action.export')}: ${r.rows}`))
              .catch((err: unknown) => notify(errorMessage(err), 'error'))
          }
        >
          {t('action.export')}
        </Button>
        <Button variant="danger" onClick={() => act(api.invoke('alerts:clear'))}>
          {t('action.clear')}
        </Button>
      </PageHeader>

      {rows.length === 0 ? (
        <Card>
          <EmptyState title={loading ? '…' : t('empty.alerts')} hint={t('empty.startMonitoring')} />
        </Card>
      ) : (
        <div className="space-y-2">
          {rows.map((alert) => (
            <AlertCard
              key={alert.id}
              alert={alert}
              language={settings.language}
              onAck={() => act(api.invoke('alerts:ack', { id: alert.id }))}
              ackLabel={t('action.acknowledge')}
            />
          ))}
        </div>
      )}
    </>
  )
}

function AlertCard({
  alert,
  language,
  onAck,
  ackLabel
}: {
  alert: AlertRecord
  language: 'ar' | 'en'
  onAck: () => void
  ackLabel: string
}): React.JSX.Element {
  const tone =
    alert.severity === 'HIGH'
      ? 'danger'
      : alert.severity === 'MEDIUM'
        ? 'warn'
        : alert.severity === 'LOW'
          ? 'accent'
          : 'neutral'
  const borderColor =
    alert.severity === 'HIGH'
      ? 'border-s-danger'
      : alert.severity === 'MEDIUM'
        ? 'border-s-warn'
        : alert.severity === 'LOW'
          ? 'border-s-accent'
          : 'border-s-line-strong'

  return (
    <article
      className={`rounded-xl border border-line border-s-[3px] bg-panel px-4 py-3 ${borderColor} ${
        alert.acknowledged ? 'opacity-55' : ''
      }`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={tone}>{alert.severity}</Badge>
        <span className="text-[13px] font-medium text-ink">{alert.title}</span>
        <Badge>{alert.kind}</Badge>
        {alert.deviceIp && <span className="mono text-xs text-muted">{alert.deviceIp}</span>}
        {alert.deviceMac && <span className="mono text-xs text-faint">{alert.deviceMac}</span>}
        <span className="ms-auto text-[11px] text-faint" title={formatDateTime(alert.ts)}>
          {formatRelative(alert.ts, language)}
        </span>
        {!alert.acknowledged && (
          <Button variant="ghost" onClick={onAck}>
            {ackLabel}
          </Button>
        )}
      </div>
      <p className="mt-1.5 text-xs leading-relaxed text-muted">{alert.reason}</p>
    </article>
  )
}
