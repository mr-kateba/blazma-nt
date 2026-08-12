import { useEffect, useState } from 'react'
import type { PcapJobStatus } from '@shared/types'
import { api, errorMessage } from '../api'
import { Badge, Button, Card, PageHeader, Select, TextInput } from '../components/ui'
import { formatBytes, formatDuration } from '../format'
import { useApp } from '../state'

export function PacketCapturePage(): React.JSX.Element {
  const { t, settings, interfaces, engine, notify } = useApp()
  const [status, setStatus] = useState<PcapJobStatus | null>(null)
  const [outputPath, setOutputPath] = useState('')
  const [filter, setFilter] = useState('')
  const [seconds, setSeconds] = useState('60')
  const [megabytes, setMegabytes] = useState('100')
  const [interfaceId, setInterfaceId] = useState(settings.interfaceId ?? engine.interfaceId ?? '')

  useEffect(() => {
    void api.invoke('pcap:status').then(setStatus).catch(() => undefined)
    return api.on('pcap:status', setStatus)
  }, [])

  const capturable = interfaces.filter((i) => i.capturable)
  const running = status?.running ?? false

  const choosePath = (): void => {
    void api
      .invoke('pcap:choosePath')
      .then((r) => r.path && setOutputPath(r.path))
      .catch((err: unknown) => notify(errorMessage(err), 'error'))
  }

  const start = (): void => {
    void api
      .invoke('pcap:start', {
        interfaceId,
        filter,
        maxSeconds: Number(seconds),
        maxMegabytes: Number(megabytes),
        outputPath
      })
      .then(setStatus)
      .catch((err: unknown) => notify(errorMessage(err), 'error'))
  }

  return (
    <>
      <PageHeader title={t('pcap.title')} description={t('pcap.explain')} />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title={t('pcap.title')}>
          <div className="space-y-3">
            <Field label={t('settings.interface')}>
              <Select
                value={interfaceId}
                onChange={setInterfaceId}
                className="w-full"
                options={
                  capturable.length === 0
                    ? [{ value: '', label: t('env.npcapMissing') }]
                    : capturable.map((i) => ({ value: i.id, label: `${i.name} ${i.ipv4[0] ? `(${i.ipv4[0]})` : ''}` }))
                }
              />
            </Field>

            <Field label={t('pcap.output')}>
              <div className="flex gap-2">
                <TextInput value={outputPath} onChange={setOutputPath} placeholder="C:\\…\\capture.pcap" className="flex-1" />
                <Button onClick={choosePath}>{t('action.browse')}</Button>
              </div>
            </Field>

            <div className="grid grid-cols-2 gap-3">
              <Field label={t('pcap.duration')}>
                <TextInput value={seconds} onChange={setSeconds} type="number" className="w-full" />
              </Field>
              <Field label={t('pcap.maxSize')}>
                <TextInput value={megabytes} onChange={setMegabytes} type="number" className="w-full" />
              </Field>
            </div>

            <Field label={t('pcap.filter')}>
              <TextInput value={filter} onChange={setFilter} placeholder="tcp port 80 and host 192.168.1.10" className="w-full" />
              <p className="mt-1 text-[11px] leading-relaxed text-faint">
                Standard BPF syntax. Only recognised keywords are accepted; anything else is rejected before the
                capture tool is invoked.
              </p>
            </Field>

            <div className="flex gap-2 pt-1">
              {running ? (
                <Button variant="danger" onClick={() => void api.invoke('pcap:stop').then(setStatus)}>
                  {t('pcap.stop')}
                </Button>
              ) : (
                <Button variant="primary" onClick={start} disabled={!interfaceId || !outputPath}>
                  {t('pcap.start')}
                </Button>
              )}
            </div>
          </div>
        </Card>

        <Card title={t('col.status')}>
          {!status || (!running && !status.outputPath) ? (
            <p className="text-sm text-muted">{t('empty.noData')}</p>
          ) : (
            <div className="space-y-2.5 text-[13px]">
              <Row label={t('col.status')}>
                {running ? <Badge tone="ok">{t('pcap.running')}</Badge> : <Badge>{t('engine.stopped')}</Badge>}
              </Row>
              <Row label={t('pcap.output')}>
                <span className="mono break-all text-xs text-muted">{status.outputPath ?? '—'}</span>
              </Row>
              <Row label={t('pcap.written')}>
                <span className="tnum">{formatBytes(status.bytesWritten)}</span>
              </Row>
              <Row label={t('col.duration')}>
                <span className="tnum">{formatDuration(status.secondsElapsed * 1000)}</span>
              </Row>
              {status.error && (
                <div className="rounded-lg border border-danger/40 bg-danger-soft px-3 py-2 text-xs text-danger">
                  {status.error}
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    </>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }): React.JSX.Element {
  return (
    <label className="block">
      <span className="mb-1 block text-[11px] uppercase tracking-wide text-faint">{label}</span>
      {children}
    </label>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }): React.JSX.Element {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-muted">{label}</span>
      {children}
    </div>
  )
}
