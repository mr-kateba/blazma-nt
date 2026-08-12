import { statSync } from 'node:fs'
import { BrowserWindow, dialog, ipcMain, Notification } from 'electron'
import { runExport } from '../backend/analytics/export.js'
import { isTimeRange, resolveRange } from '../backend/analytics/ranges.js'
import { buildReport } from '../backend/analytics/report.js'
import { buildEnvironmentReport } from '../backend/capture/environment.js'
import { PcapJob } from '../backend/capture/pcapJob.js'
import type { EventBus } from '../backend/core/bus.js'
import type { Engine } from '../backend/core/engine.js'
import type { SettingsManager } from '../backend/core/settings.js'
import type { RouterManager } from '../backend/router/manager.js'
import type { Store } from '../backend/database/store.js'
import { listInterfaces } from '../backend/devices/interfaces.js'
import { ValidationError, validateInt, validateSavePath, validateSearchText } from '../backend/security/validate.js'
import { codedError } from '../shared/errors.js'
import type { Logger } from '../backend/utils/logger.js'
import { API_CHANNELS, EVENT_CHANNELS, type ApiChannel, type ApiMap } from '../shared/ipc.js'
import type { AlertSeverity, TimeRange } from '../shared/types.js'

const SCOPE = 'ipc'
const ONLINE_WINDOW_MS = 120_000
const SEVERITY_ORDER: Record<AlertSeverity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3 }

export interface IpcContext {
  store: Store
  bus: EventBus
  engine: Engine
  settings: SettingsManager
  router: RouterManager
  log: Logger
  getWindow: () => BrowserWindow | null
}

type Handler<C extends ApiChannel> = (payload: ApiMap[C]['req']) => Promise<ApiMap[C]['res']> | ApiMap[C]['res']

export function registerIpc(ctx: IpcContext): () => void {
  const { store, bus, engine, settings, router, log } = ctx
  const pcapJob = new PcapJob(bus, log)

  /** Wraps a router action so its errors reach the UI as coded messages. */
  const routerAction = async <T,>(fn: () => Promise<T>): Promise<T> => {
    try {
      return await fn()
    } catch (err) {
      if (err instanceof Error && /^E_ROUTER_/.test(err.message)) throw err
      throw codedError('E_ROUTER_ACTION', err instanceof Error ? err.message : String(err))
    }
  }

  const range = (value: unknown): TimeRange => (isTimeRange(value) ? value : '15m')

  /** Save dialog anchored to the app window when one exists. */
  const showSave = (options: Electron.SaveDialogOptions): Promise<Electron.SaveDialogReturnValue> => {
    const window = ctx.getWindow()
    return window ? dialog.showSaveDialog(window, options) : dialog.showSaveDialog(options)
  }

  const handlers: { [C in ApiChannel]: Handler<C> } = {
    'env:report': () => buildEnvironmentReport(),

    'iface:list': async () => {
      const env = await buildEnvironmentReport()
      const dumpcap = env.backends.find((b) => b.id === 'npcap-dumpcap')
      return listInterfaces(dumpcap?.toolPath ?? null)
    },

    'engine:start': async ({ interfaceId }) => {
      const env = await buildEnvironmentReport()
      const dumpcap = env.backends.find((b) => b.id === 'npcap-dumpcap')
      const interfaces = await listInterfaces(dumpcap?.toolPath ?? null)
      const iface = interfaces.find((i) => i.id === interfaceId)
      if (!iface) {
        throw codedError('E_IFACE_UNKNOWN', 'The selected interface no longer exists. Refresh the list.')
      }
      settings.update({ interfaceId })
      return engine.start(iface)
    },

    'engine:stop': () => engine.stop(),
    'engine:status': () => engine.getStatus(),

    'devices:list': ({ includeIgnored }) =>
      store.listDevices(Boolean(includeIgnored), Date.now() - ONLINE_WINDOW_MS),

    'devices:detail': ({ id, range: r }) => {
      const deviceId = validateInt(id, 1, Number.MAX_SAFE_INTEGER, 'Device id')
      const device = store.getDevice(deviceId, Date.now() - ONLINE_WINDOW_MS)
      if (!device) return null
      const { from, to, bucketMs } = resolveRange(range(r))
      const ip = device.ipv4 ?? device.ipv6 ?? ''
      return {
        device,
        series: store.deviceSeries(deviceId, from, to, bucketMs),
        topDestinations: ip ? store.topDestinationsForDevice(ip, from) : [],
        topProtocols: ip ? store.topProtocolsForDevice(ip, from) : [],
        flows: ip ? store.flowsForDevice(ip, 200) : [],
        dns: ip ? store.dnsForDevice(ip, 100) : []
      }
    },

    'devices:setFlags': ({ id, paused, ignored, label }) => {
      const deviceId = validateInt(id, 1, Number.MAX_SAFE_INTEGER, 'Device id')
      const safeLabel = label === null ? null : label === undefined ? undefined : String(label).slice(0, 64)
      store.setDeviceFlags(deviceId, { paused, ignored, label: safeLabel })
      return store.getDevice(deviceId, Date.now() - ONLINE_WINDOW_MS)
    },

    'flows:query': (query) =>
      store.queryFlows({
        ...query,
        text: validateSearchText(query?.text),
        limit: query?.limit ? validateInt(query.limit, 1, 5000, 'limit') : 200
      }),

    'flows:active': () => store.queryFlows({ from: Date.now() - 60_000, limit: 500, sortBy: 'lastSeen' }).rows,

    'protocols:list': ({ range: r }) => store.protocolTotals(resolveRange(range(r)).from),

    'dns:list': (opts) =>
      store.listDns({
        ...opts,
        text: validateSearchText(opts?.text),
        deviceIp: validateSearchText(opts?.deviceIp, 64)
      }),

    'dns:clear': () => {
      const deleted = store.purge('dns')
      log.info(SCOPE, `DNS history cleared by user (${deleted} rows).`)
      return { deleted }
    },

    'unencrypted:list': (opts) => store.listUnencrypted({ ...opts, text: validateSearchText(opts?.text) }),

    'tls:list': (opts) => store.listTls({ ...opts, text: validateSearchText(opts?.text) }),

    'stats:snapshot': () => {
      const from = Date.now() - 15 * 60_000
      const devices = store.listDevices(false, Date.now() - ONLINE_WINDOW_MS)
      return {
        devicesTotal: devices.length,
        devicesOnline: devices.filter((d) => d.online).length,
        bytesTotal: devices.reduce((sum, d) => sum + d.bytesUp + d.bytesDown, 0),
        bytesUp: devices.reduce((sum, d) => sum + d.bytesUp, 0),
        bytesDown: devices.reduce((sum, d) => sum + d.bytesDown, 0),
        activeConnections: store.queryFlows({ from: Date.now() - 60_000, limit: 1 }).total,
        packetsPerSec: 0,
        bytesPerSec: 0,
        topTalkers: store.topTalkers(from, 6),
        topProtocols: store.topProtocols(from, 6),
        topDestinations: store.topDestinations(from, 6)
      }
    },

    'stats:series': ({ range: r }) => {
      const { from, to, bucketMs } = resolveRange(range(r))
      return store.trafficSeries(from, to, bucketMs)
    },

    'alerts:list': (opts) => store.listAlerts(opts ?? {}),
    'alerts:ack': ({ id }) => ({ updated: store.ackAlerts(id === 'all' ? 'all' : validateInt(id, 1, Number.MAX_SAFE_INTEGER, 'Alert id')) }),
    'alerts:clear': () => ({ deleted: store.purge('alerts') }),

    'analytics:report': ({ range: r }) => buildReport(store, range(r)),

    'pcap:start': async (options) => {
      const env = await buildEnvironmentReport()
      const dumpcap = env.backends.find((b) => b.id === 'npcap-dumpcap')
      if (!dumpcap?.available || !dumpcap.toolPath) {
        throw new ValidationError(dumpcap?.reason ?? 'Packet capture requires Npcap and dumpcap.')
      }
      return pcapJob.start(options, dumpcap.toolPath, dumpcap.version)
    },
    'pcap:stop': () => pcapJob.stop(),
    'pcap:status': () => pcapJob.getStatus(),
    'pcap:choosePath': async () => {
      const result = await showSave({
        title: 'Save packet capture',
        defaultPath: `blazma-capture-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.pcap`,
        filters: [{ name: 'Packet capture', extensions: ['pcap', 'pcapng'] }]
      })
      return { path: result.canceled || !result.filePath ? null : result.filePath }
    },

    'settings:get': () => settings.get(),
    'settings:set': (patch) => {
      const next = settings.update(patch ?? {})
      log.setLevel(next.logLevel)
      return next
    },

    'db:purge': ({ scope }) => {
      const allowed = ['all', 'dns', 'flows', 'alerts', 'stats'] as const
      if (!allowed.includes(scope)) throw new ValidationError('Unknown purge scope.')
      const deleted = store.purge(scope)
      log.warn(SCOPE, `User purged "${scope}" (${deleted} rows).`)
      return { deleted }
    },

    'db:stats': () => {
      let sizeBytes = 0
      try {
        sizeBytes = statSync(store.path).size
      } catch {
        // A brand new database may not be on disk yet.
      }
      return { sizeBytes, tables: store.tableStats() }
    },

    'logs:list': ({ limit, level }) => store.listLogs(limit ?? 500, level),
    'logs:clear': () => {
      store.db.prepare('DELETE FROM logs').run()
      const deleted = Number(store.db.prepare('SELECT changes() AS n').get<{ n: number }>()?.n ?? 0)
      return { deleted }
    },

    'router:detect': () => router.detect(),
    'router:status': () => router.getStatus(),
    'router:connect': ({ username, password, save }) => {
      if (typeof username !== 'string' || typeof password !== 'string') {
        throw new ValidationError('Username and password are required.')
      }
      return router.connect(username.slice(0, 128), password.slice(0, 256), Boolean(save))
    },
    'router:disconnect': () => {
      router.disconnect()
      return router.getStatus()
    },
    'router:forget': () => {
      router.forget()
      return router.getStatus()
    },
    'router:devices': () => routerAction(() => router.devices()),
    'router:signal': () => routerAction(() => router.signal()),
    'router:block': async ({ mac }) => {
      await routerAction(() => router.block(String(mac)))
      return { ok: true as const }
    },
    'router:unblock': async ({ mac }) => {
      await routerAction(() => router.unblock(String(mac)))
      return { ok: true as const }
    },
    'router:getDns': () => routerAction(() => router.getDns()),
    'router:setDns': async ({ primary, secondary }) => {
      const ip = (v: string | null): string | null => {
        if (v === null || v === '') return null
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) throw new ValidationError('DNS must be an IPv4 address.')
        return v
      }
      await routerAction(() => router.setDns(ip(primary), ip(secondary)))
      return { ok: true as const }
    },
    'router:reboot': async () => {
      await routerAction(() => router.reboot())
      return { ok: true as const }
    },

    'export:run': async ({ dataset, format, range: r }) => {
      const result = await showSave({
        title: `Export ${dataset}`,
        defaultPath: `blazma-${dataset}-${new Date().toISOString().slice(0, 10)}.${format}`,
        filters: [{ name: format.toUpperCase(), extensions: [format] }]
      })
      if (result.canceled || !result.filePath) return { path: null, rows: 0 }
      const path = validateSavePath(result.filePath, ['.csv', '.json', '.pdf'])
      const rows = runExport(store, dataset, format, range(r), path)
      log.info(SCOPE, `Exported ${rows} ${dataset} rows to ${format.toUpperCase()}.`)
      return { path, rows }
    }
  }

  for (const channel of API_CHANNELS) {
    ipcMain.handle(channel, async (_event, payload: unknown) => {
      try {
        return await (handlers[channel] as (p: unknown) => unknown)(payload)
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        if (!(err instanceof ValidationError)) log.error(SCOPE, `${channel} failed: ${message}`)
        throw new Error(message)
      }
    })
  }

  // Forward backend events to the renderer.
  const unsubscribes = EVENT_CHANNELS.map((channel) =>
    bus.on(channel, (payload) => {
      const window = ctx.getWindow()
      if (window && !window.isDestroyed()) window.webContents.send(channel, payload)
    })
  )

  // Desktop notifications for alerts at or above the configured severity.
  unsubscribes.push(
    bus.on('alerts:new', (alerts) => {
      const config = settings.get()
      if (!config.notificationsEnabled || !Notification.isSupported()) return
      for (const alert of alerts.slice(0, 3)) {
        if (SEVERITY_ORDER[alert.severity] < SEVERITY_ORDER[config.notifyMinSeverity]) continue
        const body = [alert.deviceIp && `Device: ${alert.deviceIp}`, alert.deviceMac && `MAC: ${alert.deviceMac}`]
          .filter(Boolean)
          .join('\n')
        new Notification({ title: alert.title, body: body || alert.reason.slice(0, 160) }).show()
      }
    })
  )

  return () => {
    for (const off of unsubscribes) off()
    for (const channel of API_CHANNELS) ipcMain.removeHandler(channel)
  }
}
