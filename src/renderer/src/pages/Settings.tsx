import { api, errorMessage } from '../api'
import { Badge, Button, Card, PageHeader, Select, Toggle } from '../components/ui'
import { formatBytes } from '../format'
import { useApp, useAsync } from '../state'

export function SettingsPage(): React.JSX.Element {
  const { t, settings, env, interfaces, updateSettings, notify, refreshInterfaces } = useApp()
  const dbStats = useAsync(() => api.invoke('db:stats'), [])

  const purge = (scope: 'all' | 'dns' | 'flows' | 'alerts' | 'stats'): void => {
    if (!window.confirm(t('settings.purgeConfirm'))) return
    void api
      .invoke('db:purge', { scope })
      .then((r) => {
        notify(`${t('settings.purge')}: ${r.deleted}`)
        dbStats.reload()
      })
      .catch((err: unknown) => notify(errorMessage(err), 'error'))
  }

  return (
    <>
      <PageHeader title={t('nav.settings')} />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title={t('settings.capture')}>
          <EnvironmentPanel />
        </Card>

        <Card title={t('settings.privacy')}>
          <Toggle
            checked={settings.privacyMode}
            onChange={(value) => void updateSettings({ privacyMode: value })}
            label={t('settings.privacyMode')}
            help={t('settings.privacyModeHelp')}
          />
          <Toggle
            checked={settings.storeDnsQueries}
            onChange={(value) => void updateSettings({ storeDnsQueries: value })}
            label={t('settings.storeDns')}
          />
          <Toggle
            checked={settings.storeUnencryptedMetadata}
            onChange={(value) => void updateSettings({ storeUnencryptedMetadata: value })}
            label={t('settings.storeUnencrypted')}
          />
          <p className="mt-2 rounded-lg border border-line bg-bg-elevated px-3 py-2 text-[11px] leading-relaxed text-muted">
            {t('settings.telemetry')}
          </p>
        </Card>

        <Card title={t('settings.interface')}>
          <div className="space-y-2">
            <Select
              value={settings.interfaceId ?? ''}
              onChange={(value) => void updateSettings({ interfaceId: value })}
              className="w-full"
              options={[
                { value: '', label: t('engine.selectInterface') },
                ...interfaces.map((i) => ({ value: i.id, label: `${i.name} — ${i.description}` }))
              ]}
            />
            <Button onClick={() => void refreshInterfaces()}>{t('action.refresh')}</Button>
            <div className="mt-2 max-h-64 space-y-1.5 overflow-y-auto">
              {interfaces.map((i) => (
                <div key={i.id} className="rounded-lg border border-line bg-bg-elevated px-3 py-2 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-ink">{i.name}</span>
                    <Badge tone={i.status === 'Up' ? 'ok' : 'neutral'}>{i.status}</Badge>
                    {i.capturable ? <Badge tone="accent">capturable</Badge> : <Badge tone="warn">no capture device</Badge>}
                    {i.isVirtual && <Badge>virtual</Badge>}
                  </div>
                  <div className="mono mt-1 space-y-0.5 text-[11px] text-muted">
                    <div className="truncate">{i.description}</div>
                    <div>
                      IPv4: {i.ipv4[0] ?? '—'}
                      {i.prefixLength ? `/${i.prefixLength}` : ''} · GW: {i.gateway ?? '—'}
                    </div>
                    <div className="truncate">IPv6: {i.ipv6[0] ?? '—'}</div>
                    <div>
                      MAC: {i.mac ?? '—'} · {i.speedBps ? `${(i.speedBps / 1e6).toFixed(0)} Mbps` : '—'}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Card>

        <Card title={`${t('settings.theme')} · ${t('settings.language')} · ${t('settings.performance')}`}>
          <Row label={t('settings.theme')}>
            <Select
              value={settings.theme}
              onChange={(value) => void updateSettings({ theme: value })}
              options={[
                { value: 'dark' as const, label: 'Dark' },
                { value: 'light' as const, label: 'Light' },
                { value: 'system' as const, label: 'System' }
              ]}
            />
          </Row>
          <Row label={t('settings.language')}>
            <Select
              value={settings.language}
              onChange={(value) => void updateSettings({ language: value })}
              options={[
                { value: 'ar' as const, label: 'العربية (RTL)' },
                { value: 'en' as const, label: 'English' }
              ]}
            />
          </Row>
          <Row label={t('settings.uiRate')}>
            <Select
              value={String(settings.uiUpdateHz)}
              onChange={(value) => void updateSettings({ uiUpdateHz: Number(value) })}
              options={[1, 2, 4, 8].map((hz) => ({ value: String(hz), label: `${hz} Hz` }))}
            />
          </Row>
          <Row label={t('settings.maxLiveFlows')}>
            <Select
              value={String(settings.maxLiveFlows)}
              onChange={(value) => void updateSettings({ maxLiveFlows: Number(value) })}
              options={[100, 250, 500, 1000, 2000].map((n) => ({ value: String(n), label: String(n) }))}
            />
          </Row>
          <Row label={t('settings.logLevel')}>
            <Select
              value={settings.logLevel}
              onChange={(value) => void updateSettings({ logLevel: value })}
              options={(['DEBUG', 'INFO', 'WARNING', 'ERROR'] as const).map((l) => ({ value: l, label: l }))}
            />
          </Row>
        </Card>

        <Card title={t('settings.notifications')}>
          <Toggle
            checked={settings.notificationsEnabled}
            onChange={(value) => void updateSettings({ notificationsEnabled: value })}
            label={t('settings.notifications')}
          />
          <Row label={t('settings.notifyMin')}>
            <Select
              value={settings.notifyMinSeverity}
              onChange={(value) => void updateSettings({ notifyMinSeverity: value })}
              options={(['INFO', 'LOW', 'MEDIUM', 'HIGH'] as const).map((s) => ({ value: s, label: s }))}
            />
          </Row>
        </Card>

        <Card title={t('settings.database')}>
          <Row label={t('settings.retention')}>
            <Select
              value={settings.retention}
              onChange={(value) => void updateSettings({ retention: value })}
              options={[
                { value: '1d' as const, label: '1 day' },
                { value: '7d' as const, label: '7 days' },
                { value: '30d' as const, label: '30 days' },
                { value: '90d' as const, label: '90 days' },
                { value: 'unlimited' as const, label: 'Unlimited' }
              ]}
            />
          </Row>
          <Row label={t('settings.dbSize')}>
            <span className="tnum text-sm">{formatBytes(dbStats.data?.sizeBytes ?? 0)}</span>
          </Row>

          <div className="mt-3 max-h-40 overflow-y-auto rounded-lg border border-line bg-bg-elevated p-2 text-[11px]">
            {(dbStats.data?.tables ?? []).map((table) => (
              <div key={table.name} className="flex justify-between py-0.5">
                <span className="mono text-muted">{table.name}</span>
                <span className="tnum text-faint">{table.rows}</span>
              </div>
            ))}
          </div>

          <div className="mt-3 flex flex-wrap gap-2">
            <Button onClick={() => purge('dns')}>DNS</Button>
            <Button onClick={() => purge('flows')}>{t('nav.connections')}</Button>
            <Button onClick={() => purge('alerts')}>{t('nav.alerts')}</Button>
            <Button onClick={() => purge('stats')}>{t('stat.traffic')}</Button>
            <Button variant="danger" onClick={() => purge('all')}>
              {t('settings.purgeAll')}
            </Button>
          </div>
        </Card>
      </div>

      <p className="mt-4 rounded-lg border border-line bg-panel px-4 py-3 text-xs leading-relaxed text-muted">
        {t('legal.notice')}
      </p>
      {env && (
        <p className="mt-2 text-[11px] text-faint">
          Electron {env.electronVersion} · Node {env.nodeVersion} · {env.platform}
        </p>
      )}
    </>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }): React.JSX.Element {
  return (
    <div className="flex items-center justify-between gap-3 py-1.5">
      <span className="text-[13px] text-muted">{label}</span>
      {children}
    </div>
  )
}

export function EnvironmentPanel(): React.JSX.Element {
  const { t, env } = useApp()
  if (!env) return <span className="text-sm text-muted">…</span>

  return (
    <div className="space-y-2 text-[13px]">
      <div className="flex items-center gap-2">
        <Badge tone={env.npcapInstalled ? 'ok' : 'danger'}>Npcap</Badge>
        <span className="text-muted">
          {env.npcapInstalled ? (env.npcapVersion ?? 'installed') : t('env.npcapMissing')}
        </span>
      </div>
      {!env.npcapInstalled && (
        <p className="rounded-lg border border-danger/40 bg-danger-soft px-3 py-2 text-xs leading-relaxed text-danger">
          {t('env.npcapHelp')}
        </p>
      )}

      {env.backends.map((backend) => (
        <div key={backend.id} className="rounded-lg border border-line bg-bg-elevated px-3 py-2">
          <div className="flex items-center gap-2">
            <Badge tone={backend.available ? 'ok' : 'neutral'}>{backend.id}</Badge>
            {backend.requiresElevation && <Badge tone="warn">admin</Badge>}
            {env.selectedBackend === backend.id && <Badge tone="accent">active</Badge>}
          </div>
          {backend.version && <div className="mono mt-1 truncate text-[11px] text-muted">{backend.version}</div>}
          {backend.toolPath && <div className="mono mt-0.5 truncate text-[11px] text-faint">{backend.toolPath}</div>}
          {/* Backend reasons are English diagnostics; let each pick its own direction. */}
          {backend.reason && (
            <div dir="auto" className="mt-1 text-start text-[11px] leading-relaxed text-muted">
              {backend.reason}
            </div>
          )}
        </div>
      ))}

      <div className="flex items-center gap-2 pt-1">
        <Badge tone={env.elevated ? 'ok' : 'neutral'}>{env.elevated ? 'Administrator' : t('env.notElevated')}</Badge>
      </div>
    </div>
  )
}
