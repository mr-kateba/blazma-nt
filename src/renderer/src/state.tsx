import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode
} from 'react'
import type {
  AlertRecord,
  AppSettings,
  DashboardSnapshot,
  DeviceRecord,
  DnsQueryRecord,
  EngineStatus,
  EnvironmentReport,
  LiveFlowUpdate,
  NetworkInterfaceInfo,
  TlsSessionRecord,
  TrafficSample,
  UnencryptedEvent
} from '@shared/types'
import type { Language } from '@shared/types'
import { api, errorMessage } from './api'
import { translator, translateError, isRtl, type TranslationKey } from './i18n'

const MAX_SERIES_POINTS = 300
const MAX_LIVE_ROWS = 400

interface AppState {
  ready: boolean
  settings: AppSettings
  env: EnvironmentReport | null
  interfaces: NetworkInterfaceInfo[]
  engine: EngineStatus
  snapshot: DashboardSnapshot | null
  series: TrafficSample[]
  liveFlows: LiveFlowUpdate[]
  devices: DeviceRecord[]
  dns: DnsQueryRecord[]
  unencrypted: UnencryptedEvent[]
  tls: TlsSessionRecord[]
  alerts: AlertRecord[]
  toast: { message: string; kind: 'error' | 'info' } | null
  t: (key: TranslationKey) => string
  rtl: boolean
  refreshInterfaces: () => Promise<void>
  updateSettings: (patch: Partial<AppSettings>) => Promise<void>
  startEngine: (interfaceId: string) => Promise<void>
  stopEngine: () => Promise<void>
  notify: (message: string, kind?: 'error' | 'info') => void
  dismissToast: () => void
}

const Context = createContext<AppState | null>(null)

const FALLBACK_SETTINGS: AppSettings = {
  interfaceId: null,
  autoStart: false,
  privacyMode: false,
  storeDnsQueries: true,
  storeUnencryptedMetadata: true,
  retention: '7d',
  notificationsEnabled: true,
  notifyMinSeverity: 'MEDIUM',
  theme: 'dark',
  language: 'ar',
  uiUpdateHz: 2,
  maxLiveFlows: 500,
  logLevel: 'INFO',
  telemetry: false
}

const FALLBACK_ENGINE: EngineStatus = {
  state: 'stopped',
  interfaceId: null,
  interfaceName: null,
  backend: null,
  startedAt: null,
  error: null,
  privacyMode: false,
  droppedPackets: 0,
  packetsProcessed: 0,
  bytesProcessed: 0
}

export function AppStateProvider({ children }: { children: ReactNode }): React.JSX.Element {
  const [ready, setReady] = useState(false)
  const [settings, setSettings] = useState<AppSettings>(FALLBACK_SETTINGS)
  const [env, setEnv] = useState<EnvironmentReport | null>(null)
  const [interfaces, setInterfaces] = useState<NetworkInterfaceInfo[]>([])
  const [engine, setEngine] = useState<EngineStatus>(FALLBACK_ENGINE)
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null)
  const [series, setSeries] = useState<TrafficSample[]>([])
  const [liveFlows, setLiveFlows] = useState<LiveFlowUpdate[]>([])
  const [devices, setDevices] = useState<DeviceRecord[]>([])
  const [dns, setDns] = useState<DnsQueryRecord[]>([])
  const [unencrypted, setUnencrypted] = useState<UnencryptedEvent[]>([])
  const [tls, setTls] = useState<TlsSessionRecord[]>([])
  const [alerts, setAlerts] = useState<AlertRecord[]>([])
  const [toast, setToast] = useState<AppState['toast']>(null)

  // Kept in a ref so notify() stays a stable callback while still translating
  // with the language that is current at the moment the message appears.
  const languageRef = useRef<Language>(FALLBACK_SETTINGS.language)
  languageRef.current = settings.language

  const notify = useCallback((message: string, kind: 'error' | 'info' = 'info') => {
    setToast({ message: translateError(message, languageRef.current), kind })
  }, [])

  const dismissToast = useCallback(() => setToast(null), [])

  // Initial load.
  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const [loadedSettings, loadedEnv, status, loadedSeries, loadedAlerts, loadedDevices] = await Promise.all([
          api.invoke('settings:get'),
          api.invoke('env:report'),
          api.invoke('engine:status'),
          api.invoke('stats:series', { range: '15m' }),
          api.invoke('alerts:list', { limit: 50 }),
          api.invoke('devices:list', {})
        ])
        if (cancelled) return
        setSettings(loadedSettings)
        setEnv(loadedEnv)
        setEngine(status)
        setSeries(loadedSeries)
        setAlerts(loadedAlerts.rows)
        setDevices(loadedDevices)
        setReady(true)
        const list = await api.invoke('iface:list')
        if (!cancelled) setInterfaces(list)
      } catch (err) {
        if (!cancelled) {
          notify(errorMessage(err), 'error')
          setReady(true)
        }
      }
    })()
    return () => {
      cancelled = true
    }
  }, [notify])

  // Live event subscriptions.
  useEffect(() => {
    const offs = [
      api.on('engine:status', setEngine),
      api.on('stats:tick', ({ snapshot: snap, sample }) => {
        setSnapshot(snap)
        setSeries((prev) => {
          const next = prev.length > 0 && prev[prev.length - 1].ts === sample.ts ? prev.slice(0, -1) : prev
          const merged = [...next, sample]
          return merged.length > MAX_SERIES_POINTS ? merged.slice(-MAX_SERIES_POINTS) : merged
        })
      }),
      api.on('flows:update', ({ flows, closed }) => {
        setLiveFlows((prev) => {
          const byKey = new Map(prev.map((f) => [f.key, f]))
          for (const key of closed) byKey.delete(key)
          for (const flow of flows) byKey.set(flow.key, flow)
          return [...byKey.values()].sort((a, b) => b.lastSeen - a.lastSeen).slice(0, MAX_LIVE_ROWS)
        })
      }),
      api.on('devices:update', setDevices),
      api.on('dns:update', (rows) => setDns((prev) => [...rows.reverse(), ...prev].slice(0, MAX_LIVE_ROWS))),
      api.on('unencrypted:update', (rows) =>
        setUnencrypted((prev) => [...rows.reverse(), ...prev].slice(0, MAX_LIVE_ROWS))
      ),
      api.on('tls:update', (rows) => setTls((prev) => [...rows.reverse(), ...prev].slice(0, MAX_LIVE_ROWS))),
      api.on('alerts:new', (rows) => setAlerts((prev) => [...rows.reverse(), ...prev].slice(0, 200)))
    ]
    return () => {
      for (const off of offs) off()
    }
  }, [])

  // Theme and direction follow settings.
  const appliedTheme = useThemePreference(settings.theme)
  useEffect(() => {
    const root = document.documentElement
    root.dataset.theme = appliedTheme
    root.lang = settings.language
    root.dir = isRtl(settings.language) ? 'rtl' : 'ltr'
  }, [appliedTheme, settings.language])

  const refreshInterfaces = useCallback(async () => {
    try {
      const [list, report] = await Promise.all([api.invoke('iface:list'), api.invoke('env:report')])
      setInterfaces(list)
      setEnv(report)
    } catch (err) {
      notify(errorMessage(err), 'error')
    }
  }, [notify])

  const updateSettings = useCallback(
    async (patch: Partial<AppSettings>) => {
      try {
        setSettings(await api.invoke('settings:set', patch))
      } catch (err) {
        notify(errorMessage(err), 'error')
      }
    },
    [notify]
  )

  const startEngine = useCallback(
    async (interfaceId: string) => {
      try {
        setEngine(await api.invoke('engine:start', { interfaceId }))
        setLiveFlows([])
      } catch (err) {
        notify(errorMessage(err), 'error')
      }
    },
    [notify]
  )

  const stopEngine = useCallback(async () => {
    try {
      setEngine(await api.invoke('engine:stop'))
    } catch (err) {
      notify(errorMessage(err), 'error')
    }
  }, [notify])

  const t = useMemo(() => translator(settings.language), [settings.language])

  const value: AppState = {
    ready,
    settings,
    env,
    interfaces,
    engine,
    snapshot,
    series,
    liveFlows,
    devices,
    dns,
    unencrypted,
    tls,
    alerts,
    toast,
    t,
    rtl: isRtl(settings.language),
    refreshInterfaces,
    updateSettings,
    startEngine,
    stopEngine,
    notify,
    dismissToast
  }

  return <Context.Provider value={value}>{children}</Context.Provider>
}

/** Resolves "system" to the OS preference and keeps following it. */
function useThemePreference(theme: AppSettings['theme']): 'dark' | 'light' {
  const [systemDark, setSystemDark] = useState(
    () => window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? true
  )
  useEffect(() => {
    const query = window.matchMedia?.('(prefers-color-scheme: dark)')
    if (!query) return
    const listener = (event: MediaQueryListEvent): void => setSystemDark(event.matches)
    query.addEventListener('change', listener)
    return () => query.removeEventListener('change', listener)
  }, [])
  if (theme === 'system') return systemDark ? 'dark' : 'light'
  return theme
}

export function useApp(): AppState {
  const value = useContext(Context)
  if (!value) throw new Error('useApp must be used inside AppStateProvider')
  return value
}

/** Loads data on demand and re-runs when `deps` change. */
export function useAsync<T>(
  loader: () => Promise<T>,
  deps: unknown[]
): { data: T | null; loading: boolean; error: string | null; reload: () => void } {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [nonce, setNonce] = useState(0)
  const loaderRef = useRef(loader)
  loaderRef.current = loader

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    loaderRef
      .current()
      .then((result) => {
        if (cancelled) return
        setData(result)
        setError(null)
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(errorMessage(err))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce])

  return { data, loading, error, reload: () => setNonce((n) => n + 1) }
}
