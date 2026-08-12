import { useCallback, useEffect, useState } from 'react'
import type { RouterDevice, RouterDnsConfig, RouterSignal, RouterStatus } from '@shared/router'
import { api, errorMessage } from '../api'
import { Badge, Button, Card, DataTable, EmptyState, PageHeader, TextInput, Toggle, type Column } from '../components/ui'
import { useApp } from '../state'

export function RouterControlPage(): React.JSX.Element {
  const { t, devices: monitoredDevices, notify } = useApp()
  const [status, setStatus] = useState<RouterStatus | null>(null)
  const [routerDevices, setRouterDevices] = useState<RouterDevice[]>([])
  const [signal, setSignal] = useState<RouterSignal | null>(null)
  const [busy, setBusy] = useState(false)

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await api.invoke('router:status'))
    } catch (err) {
      notify(errorMessage(err), 'error')
    }
  }, [notify])

  const refreshDevices = useCallback(async () => {
    // Sequential, not parallel: the Huawei API serializes on the backend, and
    // issuing both at once risks one call clobbering the other's session.
    try {
      setSignal(await api.invoke('router:signal'))
    } catch (err) {
      notify(errorMessage(err), 'error')
    }
    try {
      setRouterDevices(await api.invoke('router:devices'))
    } catch (err) {
      notify(errorMessage(err), 'error')
    }
  }, [notify])

  useEffect(() => {
    void refreshStatus()
    void api.invoke('router:detect').catch(() => undefined)
    return api.on('router:status', (s) => {
      setStatus(s)
      if (s.state === 'connected') void refreshDevices()
      else {
        setRouterDevices([])
        setSignal(null)
      }
    })
  }, [refreshStatus, refreshDevices])

  useEffect(() => {
    if (status?.state !== 'connected') return
    void refreshDevices()
    const timer = setInterval(() => void refreshDevices(), 15_000)
    return () => clearInterval(timer)
  }, [status?.state, refreshDevices])

  const connected = status?.state === 'connected'
  const identity = status?.identity ?? null

  return (
    <>
      <PageHeader title={t('router.title')} description={t('router.subtitle')} />

      <div className="mb-3 rounded-lg border border-warn/40 bg-warn-soft px-4 py-2.5 text-xs leading-relaxed text-warn">
        ⚡ {t('router.warnActive')}
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="xl:col-span-1">
          <ConnectionPanel status={status} busy={busy} setBusy={setBusy} onChanged={refreshStatus} />
          {connected && signal && <SignalPanel signal={signal} />}
          {connected && identity?.gatewayIp && <DnsPanel />}
        </div>

        <div className="xl:col-span-2">
          {connected ? (
            <RouterDevicesPanel
              devices={routerDevices}
              monitoredMacs={new Map(monitoredDevices.filter((d) => d.mac).map((d) => [d.mac as string, d]))}
              onRefresh={refreshDevices}
            />
          ) : (
            <Card>
              <EmptyState
                title={identity ? t('router.disconnected') : t('router.notDetected')}
                hint={identity?.note ?? undefined}
              />
            </Card>
          )}
        </div>
      </div>
    </>
  )
}

function ConnectionPanel({
  status,
  busy,
  setBusy,
  onChanged
}: {
  status: RouterStatus | null
  busy: boolean
  setBusy: (v: boolean) => void
  onChanged: () => void
}): React.JSX.Element {
  const { t, notify } = useApp()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [save, setSave] = useState(true)

  const identity = status?.identity ?? null
  const connected = status?.state === 'connected'
  const connecting = status?.state === 'connecting'

  const connect = async (): Promise<void> => {
    setBusy(true)
    try {
      await api.invoke('router:connect', { username, password, save })
      setPassword('')
      onChanged()
    } catch (err) {
      notify(errorMessage(err), 'error')
    } finally {
      setBusy(false)
    }
  }

  const act = async (channel: 'router:disconnect' | 'router:forget' | 'router:reboot'): Promise<void> => {
    if (channel === 'router:reboot' && !window.confirm(t('router.rebootConfirm'))) return
    setBusy(true)
    try {
      await api.invoke(channel)
      onChanged()
    } catch (err) {
      notify(errorMessage(err), 'error')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title={t('router.detected')} className="mb-4">
      <div className="space-y-3">
        <div className="rounded-lg border border-line bg-bg-elevated px-3 py-2.5 text-[13px]">
          {identity ? (
            <>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-ink">{identity.friendlyName ?? identity.model ?? 'Router'}</span>
                {identity.vendor !== 'unknown' && <Badge tone="accent">{identity.vendor}</Badge>}
                {connected ? (
                  <Badge tone="ok">
                    <span className="live-dot inline-block h-1.5 w-1.5 rounded-full bg-ok" />
                    {t('router.connected')}
                  </Badge>
                ) : (
                  <Badge tone="neutral">{t('router.disconnected')}</Badge>
                )}
              </div>
              <div className="mono mt-1.5 space-y-0.5 text-[11px] text-muted">
                {identity.model && <div>{t('router.model')}: {identity.model}</div>}
                <div>{t('router.gateway')}: {identity.gatewayIp}</div>
              </div>
              {!identity.controllable && (
                <div className="mt-2 text-[11px] leading-relaxed text-warn">{t('router.notControllable')}</div>
              )}
            </>
          ) : (
            <span className="text-muted">{t('router.notDetected')}</span>
          )}
        </div>

        {identity?.controllable && !connected && (
          <>
            <label className="block">
              <span className="mb-1 block text-[11px] uppercase tracking-wide text-faint">{t('router.username')}</span>
              <TextInput value={username} onChange={setUsername} className="w-full" />
              <span className="mt-1 block text-[11px] leading-relaxed text-faint">{t('router.usernameHint')}</span>
            </label>
            <label className="block">
              <span className="mb-1 block text-[11px] uppercase tracking-wide text-faint">{t('router.password')}</span>
              {/* The user types their own router password here; blazma.nt only relays it to the router. */}
              <TextInput value={password} onChange={setPassword} type="password" className="w-full" />
            </label>
            <Toggle checked={save} onChange={setSave} label={t('router.save')} />
            <p className="rounded-lg border border-line bg-bg-elevated px-3 py-2 text-[11px] leading-relaxed text-muted">
              🔒 {t('router.credentialNote')}
            </p>
            <Button variant="primary" onClick={connect} disabled={busy || connecting || !password}>
              {connecting ? t('router.connecting') : t('router.connect')}
            </Button>
          </>
        )}

        {connected && (
          <div className="flex flex-wrap gap-2">
            <Button onClick={() => void act('router:disconnect')} disabled={busy}>
              {t('router.disconnect')}
            </Button>
            <Button variant="danger" onClick={() => void act('router:reboot')} disabled={busy}>
              {t('router.reboot')}
            </Button>
            {status?.hasSavedCredentials && (
              <Button variant="ghost" onClick={() => void act('router:forget')} disabled={busy}>
                {t('router.forget')}
              </Button>
            )}
          </div>
        )}

        {status?.error && !connected && (
          <div dir="auto" className="rounded-lg border border-danger/40 bg-danger-soft px-3 py-2 text-start text-xs text-danger">
            {status.error}
          </div>
        )}
      </div>
    </Card>
  )
}

function SignalPanel({ signal }: { signal: RouterSignal }): React.JSX.Element {
  const { t } = useApp()
  return (
    <Card title={t('router.signal')} className="mb-4">
      <div className="grid grid-cols-2 gap-2 text-[13px]">
        <Metric label={t('router.network')} value={signal.networkType ?? '—'} />
        <Metric label="Bars" value={signal.bars !== null ? `${signal.bars}/5` : '—'} />
        {signal.operator && <Metric label={t('router.operator')} value={signal.operator} />}
        <Metric label="RSRP" value={signal.rsrp ?? '—'} />
        <Metric label="RSRQ" value={signal.rsrq ?? '—'} />
        <Metric label="SINR" value={signal.sinr ?? '—'} />
      </div>
    </Card>
  )
}

function Metric({ label, value }: { label: string; value: string }): React.JSX.Element {
  return (
    <div className="rounded-lg border border-line bg-bg-elevated px-3 py-2">
      <div className="text-[10px] uppercase tracking-wide text-faint">{label}</div>
      <div className="mono mt-0.5 truncate text-sm text-ink">{value}</div>
    </div>
  )
}

function DnsPanel(): React.JSX.Element {
  const { t, notify } = useApp()
  const [dns, setDns] = useState<RouterDnsConfig | null>(null)
  const [primary, setPrimary] = useState('')
  const [secondary, setSecondary] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    void api
      .invoke('router:getDns')
      .then((d) => {
        setDns(d)
        setPrimary(d.primary ?? '')
        setSecondary(d.secondary ?? '')
      })
      .catch(() => undefined)
  }, [])

  const apply = async (): Promise<void> => {
    setBusy(true)
    try {
      await api.invoke('router:setDns', { primary: primary || null, secondary: secondary || null })
      notify(t('router.dnsApply'))
    } catch (err) {
      notify(errorMessage(err), 'error')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title={t('router.dns')}>
      <div className="space-y-2">
        {dns?.automatic && primary === '' && <Badge tone="neutral">{t('router.dnsAuto')}</Badge>}
        <label className="block">
          <span className="mb-1 block text-[11px] uppercase tracking-wide text-faint">{t('router.dnsPrimary')}</span>
          <TextInput value={primary} onChange={setPrimary} placeholder="1.1.1.1" className="w-full" />
        </label>
        <label className="block">
          <span className="mb-1 block text-[11px] uppercase tracking-wide text-faint">{t('router.dnsSecondary')}</span>
          <TextInput value={secondary} onChange={setSecondary} placeholder="1.0.0.1" className="w-full" />
        </label>
        <p className="text-[11px] leading-relaxed text-faint">{t('router.dnsNote')}</p>
        <Button onClick={apply} disabled={busy}>
          {t('router.dnsApply')}
        </Button>
      </div>
    </Card>
  )
}

function RouterDevicesPanel({
  devices,
  monitoredMacs,
  onRefresh
}: {
  devices: RouterDevice[]
  monitoredMacs: Map<string, { label: string | null; hostname: string | null; vendor: string | null }>
  onRefresh: () => void
}): React.JSX.Element {
  const { t, notify } = useApp()
  const [pending, setPending] = useState<string | null>(null)

  const toggle = async (device: RouterDevice): Promise<void> => {
    const confirmMsg = device.blocked
      ? null
      : device.isSelf
        ? t('router.blockSelfConfirm')
        : t('router.blockConfirm')
    if (confirmMsg && !window.confirm(confirmMsg)) return

    setPending(device.mac)
    try {
      await api.invoke(device.blocked ? 'router:unblock' : 'router:block', { mac: device.mac })
      onRefresh()
    } catch (err) {
      notify(errorMessage(err), 'error')
    } finally {
      setPending(null)
    }
  }

  const columns: Array<Column<RouterDevice>> = [
    {
      key: 'name',
      header: t('col.device'),
      sortValue: (d) => d.hostname ?? d.mac,
      render: (d) => {
        const known = monitoredMacs.get(d.mac)
        const name = known?.label ?? known?.hostname ?? d.hostname ?? d.ip ?? d.mac
        return (
          <div className="flex items-center gap-2">
            <span className={`h-2 w-2 shrink-0 rounded-full ${d.online ? 'bg-ok' : 'bg-faint'}`} />
            <span className="truncate font-medium text-ink">{name}</span>
            {d.isSelf && <Badge tone="accent">{t('router.self')}</Badge>}
            {d.blocked && <Badge tone="danger">{t('router.blocked')}</Badge>}
          </div>
        )
      }
    },
    { key: 'ip', header: t('col.ipv4'), sortValue: (d) => d.ip ?? '', render: (d) => <span className="mono">{d.ip ?? '—'}</span> },
    { key: 'mac', header: t('col.mac'), render: (d) => <span className="mono text-muted">{d.mac}</span> },
    {
      key: 'vendor',
      header: t('col.vendor'),
      render: (d) => <span className="text-muted">{monitoredMacs.get(d.mac)?.vendor ?? '—'}</span>
    },
    {
      key: 'action',
      header: '',
      align: 'end',
      render: (d) => (
        <Button
          variant={d.blocked ? 'default' : 'danger'}
          onClick={() => void toggle(d)}
          disabled={pending === d.mac}
        >
          {d.blocked ? t('router.unblock') : t('router.block')}
        </Button>
      )
    }
  ]

  return (
    <Card
      title={t('router.devices')}
      action={
        <Button variant="ghost" onClick={onRefresh}>
          ⟳ {t('router.refresh')}
        </Button>
      }
      className="overflow-hidden"
    >
      <DataTable
        rows={devices}
        columns={columns}
        rowKey={(d) => d.mac}
        emptyTitle={t('router.noDevices')}
        maxHeight="calc(100vh - 320px)"
        initialSort={{ key: 'name', dir: 'asc' }}
      />
    </Card>
  )
}
