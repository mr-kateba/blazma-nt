import type {
  AlertRecord,
  AnalyticsReport,
  AppSettings,
  DashboardSnapshot,
  DeviceRecord,
  DnsQueryRecord,
  EngineStatus,
  EnvironmentReport,
  FlowQuery,
  FlowRecord,
  LogEntry,
  LogLevel,
  NetworkInterfaceInfo,
  PcapJobOptions,
  PcapJobStatus,
  ProtocolStat,
  TimeRange,
  TlsSessionRecord,
  TrafficSample,
  UnencryptedEvent
} from './types.js'
import type { RouterDevice, RouterDnsConfig, RouterIdentity, RouterSignal, RouterStatus } from './router.js'

export type ExportFormat = 'csv' | 'json' | 'pdf'
export type ExportDataset = 'devices' | 'connections' | 'traffic' | 'alerts' | 'dns'

/**
 * Every renderer -> backend call. The preload bridge exposes exactly these and
 * nothing else; there is no generic "invoke arbitrary channel" escape hatch.
 */
export interface ApiMap {
  'env:report': { req: void; res: EnvironmentReport }

  'iface:list': { req: void; res: NetworkInterfaceInfo[] }

  'engine:start': { req: { interfaceId: string }; res: EngineStatus }
  'engine:stop': { req: void; res: EngineStatus }
  'engine:status': { req: void; res: EngineStatus }

  'devices:list': { req: { includeIgnored?: boolean }; res: DeviceRecord[] }
  'devices:detail': {
    req: { id: number; range: TimeRange }
    res: {
      device: DeviceRecord
      series: TrafficSample[]
      topDestinations: Array<{ label: string; bytes: number; connections: number }>
      topProtocols: Array<{ protocol: string; bytes: number }>
      flows: FlowRecord[]
      dns: DnsQueryRecord[]
    } | null
  }
  'devices:setFlags': {
    req: { id: number; paused?: boolean; ignored?: boolean; label?: string | null }
    res: DeviceRecord | null
  }

  'flows:query': { req: FlowQuery; res: { rows: FlowRecord[]; total: number } }
  'flows:active': { req: void; res: FlowRecord[] }

  'protocols:list': { req: { range: TimeRange }; res: ProtocolStat[] }

  'dns:list': {
    req: { limit?: number; offset?: number; text?: string; deviceIp?: string }
    res: { rows: DnsQueryRecord[]; total: number }
  }
  'dns:clear': { req: void; res: { deleted: number } }

  'unencrypted:list': {
    req: { limit?: number; offset?: number; text?: string }
    res: { rows: UnencryptedEvent[]; total: number }
  }

  'tls:list': { req: { limit?: number; offset?: number; text?: string }; res: TlsSessionRecord[] }

  'stats:snapshot': { req: void; res: DashboardSnapshot }
  'stats:series': { req: { range: TimeRange }; res: TrafficSample[] }

  'alerts:list': {
    req: { limit?: number; offset?: number; onlyUnacked?: boolean }
    res: { rows: AlertRecord[]; total: number }
  }
  'alerts:ack': { req: { id: number | 'all' }; res: { updated: number } }
  'alerts:clear': { req: void; res: { deleted: number } }

  'analytics:report': { req: { range: TimeRange }; res: AnalyticsReport }

  'pcap:start': { req: PcapJobOptions; res: PcapJobStatus }
  'pcap:stop': { req: void; res: PcapJobStatus }
  'pcap:status': { req: void; res: PcapJobStatus }
  'pcap:choosePath': { req: void; res: { path: string | null } }

  'settings:get': { req: void; res: AppSettings }
  'settings:set': { req: Partial<AppSettings>; res: AppSettings }

  'db:purge': { req: { scope: 'all' | 'dns' | 'flows' | 'alerts' | 'stats' }; res: { deleted: number } }
  'db:stats': { req: void; res: { sizeBytes: number; tables: Array<{ name: string; rows: number }> } }

  'logs:list': { req: { limit?: number; level?: LogLevel }; res: LogEntry[] }
  'logs:clear': { req: void; res: { deleted: number } }

  'export:run': {
    req: { dataset: ExportDataset; format: ExportFormat; range: TimeRange }
    res: { path: string | null; rows: number }
  }

  'router:detect': { req: void; res: RouterIdentity | null }
  'router:status': { req: void; res: RouterStatus }
  'router:connect': { req: { username: string; password: string; save: boolean }; res: RouterStatus }
  'router:disconnect': { req: void; res: RouterStatus }
  'router:forget': { req: void; res: RouterStatus }
  'router:devices': { req: void; res: RouterDevice[] }
  'router:signal': { req: void; res: RouterSignal | null }
  'router:block': { req: { mac: string }; res: { ok: true } }
  'router:unblock': { req: { mac: string }; res: { ok: true } }
  'router:getDns': { req: void; res: RouterDnsConfig }
  'router:setDns': { req: { primary: string | null; secondary: string | null }; res: { ok: true } }
  'router:reboot': { req: void; res: { ok: true } }
}

export type ApiChannel = keyof ApiMap
export const API_CHANNELS = [
  'env:report',
  'iface:list',
  'engine:start',
  'engine:stop',
  'engine:status',
  'devices:list',
  'devices:detail',
  'devices:setFlags',
  'flows:query',
  'flows:active',
  'protocols:list',
  'dns:list',
  'dns:clear',
  'unencrypted:list',
  'tls:list',
  'stats:snapshot',
  'stats:series',
  'alerts:list',
  'alerts:ack',
  'alerts:clear',
  'analytics:report',
  'pcap:start',
  'pcap:stop',
  'pcap:status',
  'pcap:choosePath',
  'settings:get',
  'settings:set',
  'db:purge',
  'db:stats',
  'logs:list',
  'logs:clear',
  'export:run',
  'router:detect',
  'router:status',
  'router:connect',
  'router:disconnect',
  'router:forget',
  'router:devices',
  'router:signal',
  'router:block',
  'router:unblock',
  'router:getDns',
  'router:setDns',
  'router:reboot'
] as const satisfies readonly ApiChannel[]

export const EVENT_CHANNELS = [
  'engine:status',
  'stats:tick',
  'flows:update',
  'devices:update',
  'dns:update',
  'unencrypted:update',
  'tls:update',
  'alerts:new',
  'protocols:update',
  'pcap:status',
  'log:new',
  'router:status'
] as const
