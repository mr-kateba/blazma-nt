import { useEffect, useState } from 'react'
import type { LogEntry, LogLevel } from '@shared/types'
import { api, errorMessage } from '../api'
import { Badge, Button, Card, DataTable, PageHeader, Select, type Column } from '../components/ui'
import { formatDateTime } from '../format'
import { useApp, useAsync } from '../state'

export function LogsPage(): React.JSX.Element {
  const { t, notify } = useApp()
  const [level, setLevel] = useState<LogLevel | 'ALL'>('ALL')
  const [tick, setTick] = useState(0)

  const { data, loading, reload } = useAsync(
    () => api.invoke('logs:list', { limit: 1000, level: level === 'ALL' ? undefined : level }),
    [level, tick]
  )

  // New log lines arrive as events; refresh at most once per second.
  useEffect(() => {
    let pending = false
    const off = api.on('log:new', () => {
      if (pending) return
      pending = true
      setTimeout(() => {
        pending = false
        setTick((n) => n + 1)
      }, 1000)
    })
    return off
  }, [])

  const rows = data ?? []

  const columns: Array<Column<LogEntry>> = [
    { key: 'ts', header: t('col.time'), width: '160px', render: (r) => <span className="mono text-faint">{formatDateTime(r.ts)}</span> },
    {
      key: 'level',
      header: t('col.level'),
      width: '90px',
      render: (r) => (
        <Badge tone={r.level === 'ERROR' ? 'danger' : r.level === 'WARNING' ? 'warn' : r.level === 'DEBUG' ? 'neutral' : 'accent'}>
          {r.level}
        </Badge>
      )
    },
    { key: 'scope', header: t('col.scope'), width: '100px', render: (r) => <span className="mono text-muted">{r.scope}</span> },
    { key: 'message', header: t('col.message'), render: (r) => <span className="mono text-ink">{r.message}</span> }
  ]

  const exportLogs = (): void => {
    const text = rows.map((r) => `${new Date(r.ts).toISOString()} [${r.level}] ${r.scope}: ${r.message}`).join('\r\n')
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `blazma-logs-${new Date().toISOString().slice(0, 10)}.log`
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <>
      <PageHeader title={t('nav.logs')} description={t('settings.telemetry')}>
        <Select
          value={level}
          onChange={setLevel}
          options={[
            { value: 'ALL' as const, label: t('filter.all') },
            { value: 'DEBUG' as const, label: 'DEBUG' },
            { value: 'INFO' as const, label: 'INFO' },
            { value: 'WARNING' as const, label: 'WARNING' },
            { value: 'ERROR' as const, label: 'ERROR' }
          ]}
        />
        <Button onClick={reload}>⟳</Button>
        <Button onClick={exportLogs}>{t('log.export')}</Button>
        <Button
          variant="danger"
          onClick={() =>
            void api
              .invoke('logs:clear')
              .then(() => reload())
              .catch((err: unknown) => notify(errorMessage(err), 'error'))
          }
        >
          {t('log.clear')}
        </Button>
      </PageHeader>

      <Card className="overflow-hidden">
        <DataTable
          rows={rows}
          columns={columns}
          rowKey={(r) => String(r.id)}
          emptyTitle={loading ? '…' : t('empty.noData')}
          maxHeight="calc(100vh - 200px)"
        />
      </Card>
    </>
  )
}
