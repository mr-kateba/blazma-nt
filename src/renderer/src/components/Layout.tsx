import { useEffect, type ReactNode } from 'react'
import { useApp } from '../state'
import type { TranslationKey } from '../i18n'
import { formatBytes, formatRate } from '../format'
import { Badge, Button, Select } from './ui'

export type PageId =
  | 'dashboard'
  | 'devices'
  | 'live'
  | 'connections'
  | 'protocols'
  | 'dns'
  | 'unencrypted'
  | 'tls'
  | 'alerts'
  | 'analytics'
  | 'router'
  | 'pcap'
  | 'logs'
  | 'settings'

const NAV: Array<{ id: PageId; key: TranslationKey; icon: string; group: 1 | 2 | 3 }> = [
  { id: 'dashboard', key: 'nav.dashboard', icon: '▤', group: 1 },
  { id: 'devices', key: 'nav.devices', icon: '▣', group: 1 },
  { id: 'live', key: 'nav.live', icon: '⇄', group: 1 },
  { id: 'connections', key: 'nav.connections', icon: '⋈', group: 1 },
  { id: 'protocols', key: 'nav.protocols', icon: '◈', group: 2 },
  { id: 'dns', key: 'nav.dns', icon: '⌖', group: 2 },
  { id: 'unencrypted', key: 'nav.unencrypted', icon: '⚠', group: 2 },
  { id: 'tls', key: 'nav.tls', icon: '🔒', group: 2 },
  { id: 'alerts', key: 'nav.alerts', icon: '◉', group: 3 },
  { id: 'analytics', key: 'nav.analytics', icon: '◱', group: 3 },
  { id: 'router', key: 'nav.router', icon: '⌂', group: 3 },
  { id: 'pcap', key: 'nav.pcap', icon: '⏺', group: 3 },
  { id: 'logs', key: 'nav.logs', icon: '≡', group: 3 },
  { id: 'settings', key: 'nav.settings', icon: '⚙', group: 3 }
]

export function Layout({
  page,
  onNavigate,
  children
}: {
  page: PageId
  onNavigate: (page: PageId) => void
  children: ReactNode
}): React.JSX.Element {
  const { t, alerts } = useApp()
  const unacked = alerts.filter((a) => !a.acknowledged).length

  return (
    <div className="flex h-full w-full overflow-hidden bg-bg text-ink">
      <aside className="flex w-[212px] shrink-0 flex-col border-e border-line bg-bg-elevated">
        <div className="flex items-center gap-2.5 px-4 py-4">
          <div className="grid h-8 w-8 place-items-center rounded-lg bg-accent text-[15px] font-bold text-[#04121c]">
            b
          </div>
          <div className="min-w-0">
            <div className="truncate text-[13px] font-semibold tracking-tight">blazma.nt</div>
            <div className="truncate text-[10px] text-faint">{t('app.tagline')}</div>
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto px-2 pb-3">
          {[1, 2, 3].map((group) => (
            <div key={group} className={group > 1 ? 'mt-2 border-t border-line pt-2' : ''}>
              {NAV.filter((item) => item.group === group).map((item) => {
                const active = page === item.id
                return (
                  <button
                    key={item.id}
                    onClick={() => onNavigate(item.id)}
                    className={`mb-0.5 flex w-full items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-[13px] transition-colors ${
                      active ? 'bg-accent-soft font-medium text-accent' : 'text-muted hover:bg-panel-hover hover:text-ink'
                    }`}
                  >
                    <span className="w-4 text-center text-[12px] opacity-80">{item.icon}</span>
                    <span className="flex-1 text-start">{t(item.key)}</span>
                    {item.id === 'alerts' && unacked > 0 && (
                      <span className="tnum rounded-full bg-danger px-1.5 text-[10px] font-semibold text-white">
                        {unacked > 99 ? '99+' : unacked}
                      </span>
                    )}
                  </button>
                )
              })}
            </div>
          ))}
        </nav>

        <div className="border-t border-line px-3 py-2.5 text-[10px] leading-relaxed text-faint">
          {t('legal.notice')}
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar />
        <main className="min-h-0 flex-1 overflow-y-auto p-5">{children}</main>
      </div>

      <Toast />
    </div>
  )
}

function TopBar(): React.JSX.Element {
  const { t, engine, interfaces, settings, snapshot, startEngine, stopEngine, updateSettings, refreshInterfaces } =
    useApp()

  const capturable = interfaces.filter((i) => i.capturable)
  const selected = settings.interfaceId ?? engine.interfaceId ?? capturable[0]?.id ?? ''
  const running = engine.state === 'running'
  const busy = engine.state === 'starting' || engine.state === 'stopping'

  const stateBadge =
    engine.state === 'running' ? (
      <Badge tone="ok">
        <span className="live-dot inline-block h-1.5 w-1.5 rounded-full bg-ok" />
        {t('engine.running')}
      </Badge>
    ) : engine.state === 'error' ? (
      <Badge tone="danger">{t('engine.error')}</Badge>
    ) : engine.state === 'starting' ? (
      <Badge tone="warn">{t('engine.starting')}</Badge>
    ) : engine.state === 'stopping' ? (
      <Badge tone="warn">{t('engine.stopping')}</Badge>
    ) : (
      <Badge tone="neutral">{t('engine.stopped')}</Badge>
    )

  return (
    <header className="flex flex-wrap items-center gap-2.5 border-b border-line bg-bg-elevated px-5 py-2.5">
      {stateBadge}

      <Select
        value={selected}
        onChange={(value) => void updateSettings({ interfaceId: value })}
        options={
          interfaces.length === 0
            ? [{ value: '', label: t('engine.selectInterface') }]
            : interfaces.map((i) => ({
                value: i.id,
                label: `${i.name}${i.capturable ? '' : ' — no capture device'}${i.ipv4[0] ? ` (${i.ipv4[0]})` : ''}`
              }))
        }
        className="max-w-[320px] flex-1 min-w-[200px]"
      />

      {running ? (
        <Button variant="danger" onClick={() => void stopEngine()} disabled={busy}>
          {t('engine.stop')}
        </Button>
      ) : (
        <Button variant="primary" onClick={() => selected && void startEngine(selected)} disabled={busy || !selected}>
          {t('engine.start')}
        </Button>
      )}

      <Button variant="ghost" onClick={() => void refreshInterfaces()} title={t('action.refresh')}>
        ⟳
      </Button>

      <div className="ms-auto flex items-center gap-3 text-xs text-muted">
        {settings.privacyMode && <Badge tone="violet">{t('engine.privacyOn')}</Badge>}
        {running && snapshot && (
          <>
            <span className="tnum" title={t('stat.bytesPerSec')}>
              ↓↑ {formatRate(snapshot.bytesPerSec)}
            </span>
            <span className="tnum" title={t('stat.packetsPerSec')}>
              {snapshot.packetsPerSec} pkt/s
            </span>
            <span className="tnum" title={t('stat.traffic')}>
              Σ {formatBytes(engine.bytesProcessed)}
            </span>
          </>
        )}
        {engine.droppedPackets > 0 && <Badge tone="warn">{engine.droppedPackets} dropped</Badge>}
      </div>
    </header>
  )
}

function Toast(): React.JSX.Element | null {
  const { toast, dismissToast } = useApp()

  useEffect(() => {
    if (!toast) return
    const timer = setTimeout(dismissToast, toast.kind === 'error' ? 9000 : 4000)
    return () => clearTimeout(timer)
  }, [toast, dismissToast])

  if (!toast) return null
  return (
    <div className="fixed bottom-5 end-5 z-50 max-w-md">
      <div
        className={`flex items-start gap-3 rounded-xl border px-4 py-3 text-[13px] shadow-xl ${
          toast.kind === 'error' ? 'border-danger/40 bg-danger-soft text-danger' : 'border-line bg-panel text-ink'
        }`}
      >
        {/*
          Backend diagnostics can be English even while the UI is Arabic.
          `dir="auto"` lets each message take its direction from its own first
          strong character, which keeps trailing punctuation in place.
        */}
        <span dir="auto" className="flex-1 text-start leading-relaxed">
          {toast.message}
        </span>
        <button onClick={dismissToast} className="text-faint hover:text-ink">
          ✕
        </button>
      </div>
    </div>
  )
}
