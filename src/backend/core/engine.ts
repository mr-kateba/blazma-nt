import type {
  AlertRecord,
  CaptureBackendId,
  DashboardSnapshot,
  DnsQueryRecord,
  EngineStatus,
  LiveFlowUpdate,
  NetworkInterfaceInfo,
  TlsSessionRecord,
  TrafficSample,
  UnencryptedEvent
} from '../../shared/types.js'
import { AlertEngine, type NewAlert } from '../alerts/engine.js'
import { DumpcapSource } from '../capture/dumpcapSource.js'
import { buildEnvironmentReport } from '../capture/environment.js'
import { PktmonSource } from '../capture/pktmonSource.js'
import type { PcapPacket } from '../capture/pcapStream.js'
import type { CaptureSource } from '../capture/source.js'
import { pollNeighbors } from '../capture/systemPoller.js'
import { DeviceRegistry } from '../devices/registry.js'
import { FlowTracker, type TrackedFlow } from '../flows/tracker.js'
import { summarizeHttp } from '../parser/http.js'
import { parsePacket } from '../parser/packet.js'
import type { ParsedPacket } from '../parser/types.js'
import { codedError, codedMessage, type ErrorCode } from '../../shared/errors.js'
import type { Store } from '../database/store.js'
import { inSubnet, isPrivateIp } from '../utils/net.js'
import type { Logger } from '../utils/logger.js'
import type { EventBus } from './bus.js'
import type { SettingsManager } from './settings.js'

/** Devices are keyed by MAC when known, otherwise by IP — matching the store. */
function deviceKeyOf(device: { mac: string | null; ipv4: string | null }): string {
  return device.mac ?? `ip:${device.ipv4}`
}

const SCOPE = 'engine'
const STATS_TICK_MS = 1000
const DEVICE_ONLINE_WINDOW_MS = 120_000

interface PendingDns {
  ts: number
  deviceIp: string | null
}

/**
 * The capture pipeline.
 *
 * Packets are parsed on arrival and folded into in-memory tables. Nothing
 * per-packet ever reaches the UI or the database: once per second the engine
 * flushes aggregates (flow deltas, device counters, protocol totals) and once
 * per `uiUpdateHz` it publishes a batch of updates. This is what keeps the
 * interface responsive on a busy network.
 */
export class Engine {
  private source: CaptureSource | null = null
  private flows: FlowTracker
  private devices = new DeviceRegistry()
  private alerts = new AlertEngine()

  private status: EngineStatus = {
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

  private localSubnet: { base: string; prefix: number } | null = null
  private localIps = new Set<string>()

  private statsTimer: NodeJS.Timeout | null = null
  private publishTimer: NodeJS.Timeout | null = null
  private neighborTimer: NodeJS.Timeout | null = null
  private retentionTimer: NodeJS.Timeout | null = null

  /** Accumulators drained on each tick. */
  private tickBytesUp = 0
  private tickBytesDown = 0
  private tickPackets = 0
  private protocolTick = new Map<
    string,
    { transport: string; encryption: string; bytes: number; packets: number; connections: Set<string> }
  >()
  private pendingDnsRows: Array<Omit<DnsQueryRecord, 'id'>> = []
  private pendingUnencrypted: Array<Omit<UnencryptedEvent, 'id'>> = []
  private pendingTls: Array<Omit<TlsSessionRecord, 'id'>> = []
  private pendingAlerts: NewAlert[] = []
  private closedFlowKeys: string[] = []
  private dnsInFlight = new Map<number, PendingDns>()
  /** Hostnames learned from observed DNS answers, used to label destinations. */
  private ipToHostname = new Map<string, string>()

  constructor(
    private readonly store: Store,
    private readonly bus: EventBus,
    private readonly settings: SettingsManager,
    private readonly log: Logger
  ) {
    this.flows = new FlowTracker()
  }

  getStatus(): EngineStatus {
    return { ...this.status, privacyMode: this.settings.get().privacyMode }
  }

  private setStatus(patch: Partial<EngineStatus>): void {
    this.status = { ...this.status, ...patch }
    this.bus.emit('engine:status', this.getStatus())
  }

  async start(iface: NetworkInterfaceInfo): Promise<EngineStatus> {
    /**
     * Records the failure on the status object and returns the error to throw.
     * Returning rather than throwing keeps the `throw` at the call site, so
     * TypeScript still narrows the checks below.
     */
    const failure = (code: ErrorCode, fallback: string): Error => {
      this.setStatus({ state: 'error', error: codedMessage(code, fallback) })
      this.log.error(SCOPE, fallback)
      return codedError(code, fallback)
    }

    if (this.status.state === 'running' || this.status.state === 'starting') {
      throw failure('E_ALREADY_RUNNING', 'Monitoring is already running. Stop it before selecting another interface.')
    }

    this.setStatus({ state: 'starting', error: null, interfaceId: iface.id, interfaceName: iface.name })

    const env = await buildEnvironmentReport()
    const dumpcap = env.backends.find((b) => b.id === 'npcap-dumpcap')
    const pktmon = env.backends.find((b) => b.id === 'pktmon')

    // Prefer the live Npcap/dumpcap path; fall back to the built-in pktmon
    // engine when Npcap is not installed. Only when neither can run do we stop.
    let source: CaptureSource
    let backendId: CaptureBackendId

    if (dumpcap?.available && dumpcap.toolPath && iface.capturable) {
      backendId = 'npcap-dumpcap'
      source = new DumpcapSource({
        toolPath: dumpcap.toolPath,
        interfaceId: iface.id,
        snapLength: 1024,
        version: dumpcap.version
      })
    } else if (pktmon?.available) {
      backendId = 'pktmon'
      source = new PktmonSource({ toolPath: pktmon.toolPath ?? undefined, snapLength: 512 })
    } else if (env.npcapInstalled && dumpcap && !dumpcap.available) {
      throw failure(
        'E_DUMPCAP_MISSING',
        dumpcap.reason ??
          'Npcap is installed but dumpcap.exe was not found. Install Wireshark, which provides it.'
      )
    } else if (dumpcap?.available && !iface.capturable) {
      throw failure(
        'E_IFACE_NOT_CAPTURABLE',
        `Interface "${iface.name}" has no Npcap capture device. Choose an adapter marked as capturable.`
      )
    } else if (pktmon && !pktmon.available && pktmon.reason?.includes('Administrator')) {
      throw failure(
        'E_CAPTURE_FAILED',
        'No capture driver is available. Either install Npcap, or restart blazma.nt as Administrator to use the built-in Windows pktmon engine.'
      )
    } else {
      throw failure(
        'E_NPCAP_MISSING',
        'No packet-capture backend is available. Install Npcap (npcap.com) for the best performance, or run blazma.nt as Administrator to use the built-in Windows pktmon engine.'
      )
    }

    this.resetState(iface)

    try {
      await source.start({
        onPacket: (packet, linkType) => this.handlePacket(packet, linkType),
        onError: (message, fatal) => this.handleSourceError(message, fatal),
        onStats: ({ dropped }) => this.setStatus({ droppedPackets: dropped })
      })
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err)
      this.log.error(SCOPE, `Capture failed to start: ${detail}`)
      this.setStatus({ state: 'error', error: codedMessage('E_CAPTURE_FAILED', detail) })
      throw codedError('E_CAPTURE_FAILED', detail)
    }

    this.source = source
    this.startTimers()
    this.setStatus({ state: 'running', backend: backendId, startedAt: Date.now(), error: null })
    this.log.info(SCOPE, `Monitoring started on ${iface.name} using ${backendId}.`)
    void this.refreshNeighbors()
    return this.getStatus()
  }

  async stop(): Promise<EngineStatus> {
    if (this.source) {
      this.setStatus({ state: 'stopping' })
      await this.source.stop()
      this.source = null
    }
    this.stopTimers()
    this.flushToDatabase()
    this.setStatus({ state: 'stopped', startedAt: null, backend: null })
    this.log.info(SCOPE, 'Monitoring stopped.')
    return this.getStatus()
  }

  async shutdown(): Promise<void> {
    await this.stop()
  }

  private resetState(iface: NetworkInterfaceInfo): void {
    this.flows = new FlowTracker()
    this.devices = new DeviceRegistry()
    this.alerts = new AlertEngine()
    this.localIps = new Set([...iface.ipv4, ...iface.ipv6])
    const primary = iface.ipv4[0]
    this.localSubnet = primary && iface.prefixLength ? { base: primary, prefix: iface.prefixLength } : null
    this.tickBytesUp = 0
    this.tickBytesDown = 0
    this.tickPackets = 0
    this.protocolTick.clear()
    this.pendingDnsRows = []
    this.pendingUnencrypted = []
    this.pendingTls = []
    this.pendingAlerts = []
    this.closedFlowKeys = []
    this.dnsInFlight.clear()
    this.setStatus({ packetsProcessed: 0, bytesProcessed: 0, droppedPackets: 0 })
  }

  private startTimers(): void {
    const hz = Math.min(Math.max(this.settings.get().uiUpdateHz, 1), 10)
    this.statsTimer = setInterval(() => this.onStatsTick(), STATS_TICK_MS)
    this.publishTimer = setInterval(() => this.publish(), Math.round(1000 / hz))
    this.neighborTimer = setInterval(() => void this.refreshNeighbors(), 60_000)
    this.retentionTimer = setInterval(
      () => {
        const removed = this.store.applyRetention(this.settings.get().retention)
        if (removed > 0) this.log.debug(SCOPE, `Retention removed ${removed} rows.`)
      },
      15 * 60_000
    )
  }

  private stopTimers(): void {
    for (const timer of [this.statsTimer, this.publishTimer, this.neighborTimer, this.retentionTimer]) {
      if (timer) clearInterval(timer)
    }
    this.statsTimer = null
    this.publishTimer = null
    this.neighborTimer = null
    this.retentionTimer = null
  }

  private handleSourceError(message: string, fatal: boolean): void {
    this.log.error(SCOPE, message)
    if (!fatal) return
    this.stopTimers()
    this.source = null
    this.setStatus({ state: 'error', error: message, backend: null })
  }

  private isLocalAddress(ip: string | null): boolean {
    if (!ip) return false
    if (this.localIps.has(ip)) return true
    if (this.localSubnet && inSubnet(ip, this.localSubnet.base, this.localSubnet.prefix)) return true
    return isPrivateIp(ip)
  }

  /* ------------------------------------------------------------------ */
  /* Packet path — hot loop, no allocation beyond what the parser needs   */
  /* ------------------------------------------------------------------ */

  private handlePacket(raw: PcapPacket, linkType: number): void {
    const packet = parsePacket(raw.data, raw.ts, raw.wireLength, linkType)
    const now = packet.ts

    this.status.packetsProcessed += 1
    this.status.bytesProcessed += packet.wireLength
    this.tickPackets += 1

    const srcLocal = this.isLocalAddress(packet.srcIp)
    const dstLocal = this.isLocalAddress(packet.dstIp)

    if (srcLocal && !dstLocal) this.tickBytesUp += packet.wireLength
    else if (dstLocal && !srcLocal) this.tickBytesDown += packet.wireLength
    else this.tickBytesDown += packet.wireLength

    // Device discovery from L2/L3 addresses and from ARP/DHCP announcements.
    const srcDevice = this.devices.observe({
      mac: packet.ethSrc,
      ip: packet.srcIp,
      ts: now,
      isLocal: srcLocal,
      hostname: packet.app?.protocol === 'DHCP' ? packet.app.dhcp.hostname : null
    })
    const dstDevice = this.devices.observe({ mac: packet.ethDst, ip: packet.dstIp, ts: now, isLocal: dstLocal })

    if (srcDevice) this.devices.addTraffic(srcDevice, packet.wireLength, true)
    if (dstDevice) this.devices.addTraffic(dstDevice, packet.wireLength, false)

    if (packet.arp) {
      this.devices.observe({ mac: packet.arp.senderMac, ip: packet.arp.senderIp, ts: now, isLocal: true })
    }

    if (packet.transport === 'ARP' || packet.transport === 'OTHER') {
      this.countProtocol(packet, packet.appProtocol, null)
      return
    }

    const serverName = this.serverNameOf(packet)
    const flow = this.flows.update({
      packet,
      srcIsLocal: srcLocal,
      dstIsLocal: dstLocal,
      deviceMac: srcLocal ? packet.ethSrc : packet.ethDst,
      deviceIp: srcLocal ? packet.srcIp : packet.dstIp,
      serverName
    })

    if (!flow.remoteHostname) {
      const known = this.ipToHostname.get(flow.dstIp)
      if (known) flow.remoteHostname = known
    }

    this.countProtocol(packet, flow.appProtocol, flow.key)
    this.inspectApplicationLayer(packet, flow, now)

    if (packet.transport === 'TCP' && packet.tcpFlags?.syn && !packet.tcpFlags.ack && packet.srcIp) {
      const alert = this.alerts.observeConnection(packet.srcIp, packet.dstPort, now)
      if (alert) this.pendingAlerts.push(alert)
    }
    if (packet.confidence === 'unknown' && packet.dstPort > 0) {
      const alert = this.alerts.observeUnknownProtocol(packet.transport, packet.dstPort, now)
      if (alert) this.pendingAlerts.push(alert)
    }
  }

  private serverNameOf(packet: ParsedPacket): string | null {
    if (this.settings.get().privacyMode) return null
    if (packet.app?.protocol === 'TLS') return packet.app.tls.sni
    if (packet.app?.protocol === 'HTTP') return packet.app.http.host
    return null
  }

  private countProtocol(packet: ParsedPacket, protocol: string, flowKey: string | null): void {
    let entry = this.protocolTick.get(protocol)
    if (!entry) {
      entry = {
        transport: packet.transport,
        encryption: packet.encrypted === true ? 'encrypted' : packet.encrypted === false ? 'unencrypted' : 'unknown',
        bytes: 0,
        packets: 0,
        connections: new Set()
      }
      this.protocolTick.set(protocol, entry)
    }
    entry.bytes += packet.wireLength
    entry.packets += 1
    if (flowKey) entry.connections.add(flowKey)
  }

  /** DNS, HTTP metadata and TLS handshake details. Honours Privacy Mode. */
  private inspectApplicationLayer(packet: ParsedPacket, flow: TrackedFlow, now: number): void {
    const app = packet.app
    if (!app) return
    const settings = this.settings.get()
    const deviceIp = flow.deviceIp
    const deviceMac = flow.deviceMac

    if (app.protocol === 'DNS' || app.protocol === 'MDNS') {
      const dns = app.dns
      if (!dns.isResponse) {
        this.dnsInFlight.set(dns.id, { ts: now, deviceIp })
        const alert = this.alerts.observeDnsQuery(deviceIp, now)
        if (alert) this.pendingAlerts.push(alert)
      }

      // Answers teach us which hostname belongs to which address, which is how
      // destinations get real names instead of bare IPs.
      for (const answer of dns.answers) {
        if ((answer.type === 'A' || answer.type === 'AAAA') && answer.data) {
          this.ipToHostname.set(answer.data, dns.questions[0]?.name ?? answer.name)
          if (this.ipToHostname.size > 20_000) this.ipToHostname.clear()
        }
      }

      if (settings.privacyMode || !settings.storeDnsQueries) return
      if (dns.isResponse) {
        const pending = this.dnsInFlight.get(dns.id)
        this.dnsInFlight.delete(dns.id)
        const question = dns.questions[0]
        if (!question) return
        this.pendingDnsRows.push({
          ts: now,
          deviceIp: pending?.deviceIp ?? deviceIp,
          deviceMac,
          server: packet.srcIp ?? '',
          query: question.name,
          recordType: question.type,
          response: dns.answers.map((a) => a.data).filter(Boolean).join(', ') || null,
          responseCode: dns.responseCode,
          latencyMs: pending ? Math.max(0, Math.round(now - pending.ts)) : null
        })
      }
      return
    }

    if (app.protocol === 'TLS') {
      const tls = app.tls
      if (tls.kind === 'client-hello' || tls.kind === 'certificate' || tls.kind === 'server-hello') {
        this.pendingTls.push({
          ts: now,
          deviceIp,
          serverIp: flow.dstIp,
          serverPort: flow.dstPort,
          sni: settings.privacyMode ? null : tls.sni,
          version: tls.version,
          certSubject: settings.privacyMode ? null : tls.certSubject,
          certIssuer: settings.privacyMode ? null : tls.certIssuer,
          bytes: flow.bytesUp + flow.bytesDown,
          durationMs: Math.max(0, now - flow.firstSeen)
        })
      }
      return
    }

    // Everything below is unencrypted by definition.
    const unencryptedProtocols = ['HTTP', 'FTP', 'TELNET', 'SMTP', 'IMAP', 'POP3']
    if (!unencryptedProtocols.includes(app.protocol)) return

    const alert = this.alerts.unencryptedProtocol(
      { protocol: app.protocol, deviceIp, deviceMac, dstIp: flow.dstIp, dstPort: flow.dstPort },
      now
    )
    if (alert) this.pendingAlerts.push(alert)

    if (settings.privacyMode || !settings.storeUnencryptedMetadata) return

    const metadata =
      app.protocol === 'HTTP'
        ? summarizeHttp(app.http)
        : `${app.protocol} session observed in cleartext. [Payload not recorded]`

    this.pendingUnencrypted.push({
      ts: now,
      deviceIp,
      deviceMac,
      srcIp: flow.srcIp,
      srcPort: flow.srcPort,
      dstIp: flow.dstIp,
      dstPort: flow.dstPort,
      protocol: app.protocol,
      bytes: packet.wireLength,
      metadata,
      redacted: app.protocol === 'HTTP' ? app.http.redacted : true
    })
  }

  /* ------------------------------------------------------------------ */
  /* Aggregation ticks                                                    */
  /* ------------------------------------------------------------------ */

  private onStatsTick(): void {
    const now = Date.now()
    const bucket = Math.floor(now / 1000) * 1000

    const sample: TrafficSample = {
      ts: bucket,
      bytesUp: this.tickBytesUp,
      bytesDown: this.tickBytesDown,
      packets: this.tickPackets
    }

    const bytesPerSecond = sample.bytesUp + sample.bytesDown
    this.tickBytesUp = 0
    this.tickBytesDown = 0
    this.tickPackets = 0

    this.closedFlowKeys.push(...this.flows.expire(now))
    this.flushToDatabase(bucket, sample)

    for (const alert of this.alerts.observeBandwidth(bytesPerSecond, now)) this.pendingAlerts.push(alert)

    const snapshot = this.buildSnapshot(sample, bytesPerSecond)
    this.bus.emit('stats:tick', { snapshot, sample })
  }

  private flushToDatabase(bucket = Math.floor(Date.now() / 1000) * 1000, sample?: TrafficSample): void {
    try {
      if (sample && (sample.packets > 0 || sample.bytesUp > 0 || sample.bytesDown > 0)) {
        this.store.insertTrafficSample(sample)
      }

      const deviceDeltas = this.devices.drainDeltas()
      if (deviceDeltas.length > 0) {
        this.store.upsertDevices(
          deviceDeltas.map(({ device }) => ({
            mac: device.mac,
            ipv4: device.ipv4,
            ipv6: device.ipv6,
            hostname: device.hostname,
            vendor: device.vendor,
            label: null,
            firstSeen: device.firstSeen,
            lastSeen: device.lastSeen,
            bytesUp: device.bytesUp,
            bytesDown: device.bytesDown,
            packetsUp: device.packetsUp,
            packetsDown: device.packetsDown,
            isLocal: device.isLocal,
            paused: false,
            ignored: false
          }))
        )

        // Device rows need their database ids for the per-device time series.
        // The id cache is only rebuilt when a key we have not seen turns up, so
        // the steady state costs no queries at all.
        if (deviceDeltas.some(({ device }) => !this.deviceIds.has(deviceKeyOf(device)))) {
          this.deviceIds = new Map(
            this.store.listDevices(true, 0).map((d) => [d.mac ?? `ip:${d.ipv4}`, d.id] as const)
          )
        }
        const samples = deviceDeltas
          .map(({ device, up, down, packets }) => {
            const id = this.deviceIds.get(deviceKeyOf(device))
            return id ? { deviceId: id, bytesUp: up, bytesDown: down, packets } : null
          })
          .filter((s): s is { deviceId: number; bytesUp: number; bytesDown: number; packets: number } => s !== null)
        this.store.insertDeviceSamples(bucket, samples)

        for (const { device, up } of deviceDeltas) {
          const alert = this.alerts.observeUpload(device.ipv4, device.mac, up, bucket)
          if (alert) this.pendingAlerts.push(alert)
        }
      }

      const flowDeltas = this.flows.drainDeltas()
      if (flowDeltas.length > 0) {
        this.store.upsertFlows(
          flowDeltas.map((f) => ({
            key: f.key,
            srcIp: f.srcIp,
            srcPort: f.srcPort,
            dstIp: f.dstIp,
            dstPort: f.dstPort,
            transport: f.transport,
            appProtocol: f.appProtocol,
            confidence: f.confidence,
            encryption: f.encryption,
            direction: f.direction,
            state: f.state,
            firstSeen: f.firstSeen,
            lastSeen: f.lastSeen,
            bytesUp: f.bytesUp,
            bytesDown: f.bytesDown,
            packetsUp: f.packetsUp,
            packetsDown: f.packetsDown,
            serverName: f.serverName,
            remoteHostname: f.remoteHostname,
            deviceMac: f.deviceMac,
            deviceIp: f.deviceIp
          }))
        )
        this.lastFlowDeltas = flowDeltas
      }

      if (this.protocolTick.size > 0) {
        this.store.insertProtocolSamples(
          bucket,
          [...this.protocolTick.entries()].map(([protocol, e]) => ({
            protocol,
            transport: e.transport,
            encryption: e.encryption,
            bytes: e.bytes,
            packets: e.packets,
            connections: e.connections.size
          }))
        )
        this.protocolTick.clear()
      }

      if (this.pendingDnsRows.length > 0) {
        this.store.insertDnsQueries(this.pendingDnsRows)
        this.lastDnsRows = this.pendingDnsRows
        this.pendingDnsRows = []
      }
      if (this.pendingUnencrypted.length > 0) {
        this.store.insertUnencrypted(this.pendingUnencrypted)
        this.lastUnencrypted = this.pendingUnencrypted
        this.pendingUnencrypted = []
      }
      if (this.pendingTls.length > 0) {
        this.store.insertTlsSessions(this.pendingTls)
        this.lastTls = this.pendingTls
        this.pendingTls = []
      }

      for (const device of this.devices.drainNew()) {
        const alert = this.alerts.newDevice({ mac: device.mac, ipv4: device.ipv4, vendor: device.vendor }, bucket)
        if (alert) this.pendingAlerts.push(alert)
      }

      if (this.pendingAlerts.length > 0) {
        this.lastAlerts = this.store.insertAlerts(this.pendingAlerts)
        this.pendingAlerts = []
      }

      // Names learned from DNS get written back so old flows gain hostnames.
      for (const [ip, hostname] of this.ipToHostname) {
        if (this.hostnamesApplied.has(ip)) continue
        this.hostnamesApplied.add(ip)
        this.store.applyDnsHostname(ip, hostname)
      }
      if (this.hostnamesApplied.size > 20_000) this.hostnamesApplied.clear()
    } catch (err) {
      this.log.error(SCOPE, 'Failed to flush aggregates to the database', err)
    }
  }

  private hostnamesApplied = new Set<string>()
  private deviceIds = new Map<string, number>()
  private lastDevicePublish = 0
  private lastFlowDeltas: TrackedFlow[] = []
  private lastDnsRows: Array<Omit<DnsQueryRecord, 'id'>> = []
  private lastUnencrypted: Array<Omit<UnencryptedEvent, 'id'>> = []
  private lastTls: Array<Omit<TlsSessionRecord, 'id'>> = []
  private lastAlerts: AlertRecord[] = []

  /** Publishes batched updates to the UI at the configured rate. */
  private publish(): void {
    const settings = this.settings.get()

    if (this.lastFlowDeltas.length > 0 || this.closedFlowKeys.length > 0) {
      const flows: LiveFlowUpdate[] = this.lastFlowDeltas.slice(0, settings.maxLiveFlows).map((f) => ({
        key: f.key,
        srcIp: f.srcIp,
        srcPort: f.srcPort,
        dstIp: f.dstIp,
        dstPort: f.dstPort,
        transport: f.transport,
        appProtocol: f.appProtocol,
        encryption: f.encryption,
        direction: f.direction,
        state: f.state,
        lastSeen: f.lastSeen,
        deltaBytes: f.deltaBytes,
        deltaPackets: f.deltaPackets,
        totalBytes: f.bytesUp + f.bytesDown,
        serverName: settings.privacyMode ? null : (f.serverName ?? f.remoteHostname)
      }))
      this.bus.emit('flows:update', { flows, closed: this.closedFlowKeys })
      this.lastFlowDeltas = []
      this.closedFlowKeys = []
    }

    if (this.lastDnsRows.length > 0) {
      this.bus.emit(
        'dns:update',
        this.lastDnsRows.map((r, i) => ({ ...r, id: -1 - i }))
      )
      this.lastDnsRows = []
    }
    if (this.lastUnencrypted.length > 0) {
      this.bus.emit(
        'unencrypted:update',
        this.lastUnencrypted.map((r, i) => ({ ...r, id: -1 - i }))
      )
      this.lastUnencrypted = []
    }
    if (this.lastTls.length > 0) {
      this.bus.emit(
        'tls:update',
        this.lastTls.map((r, i) => ({ ...r, id: -1 - i }))
      )
      this.lastTls = []
    }
    if (this.lastAlerts.length > 0) {
      this.bus.emit('alerts:new', this.lastAlerts)
      this.lastAlerts = []
    }

    // The device table changes slowly and its query is the most expensive one
    // in the loop, so it is published at a fixed 0.5 Hz regardless of uiUpdateHz.
    const now = Date.now()
    if (now - this.lastDevicePublish >= 2000) {
      this.lastDevicePublish = now
      this.bus.emit('devices:update', this.store.listDevices(false, now - DEVICE_ONLINE_WINDOW_MS))
    }
  }

  private buildSnapshot(sample: TrafficSample, bytesPerSecond: number): DashboardSnapshot {
    const now = Date.now()
    const onlineCutoff = now - DEVICE_ONLINE_WINDOW_MS
    const devices = this.store.listDevices(false, onlineCutoff)
    const windowStart = now - 15 * 60_000

    let bytesUp = 0
    let bytesDown = 0
    for (const device of devices) {
      bytesUp += device.bytesUp
      bytesDown += device.bytesDown
    }

    let activeConnections = 0
    for (const flow of this.flows.values()) {
      if (flow.state !== 'CLOSED' && now - flow.lastSeen < 60_000) activeConnections += 1
    }

    return {
      devicesTotal: devices.length,
      devicesOnline: devices.filter((d) => d.online).length,
      bytesTotal: this.status.bytesProcessed,
      bytesUp,
      bytesDown,
      activeConnections,
      packetsPerSec: sample.packets,
      bytesPerSec: bytesPerSecond,
      topTalkers: this.store.topTalkers(windowStart, 6),
      topProtocols: this.store.topProtocols(windowStart, 6),
      topDestinations: this.store.topDestinations(windowStart, 6)
    }
  }

  /** ARP neighbours fill in devices that are quiet but present on the LAN. */
  private async refreshNeighbors(): Promise<void> {
    try {
      const neighbors = await pollNeighbors()
      const now = Date.now()
      for (const n of neighbors) {
        if (!this.isLocalAddress(n.ip)) continue
        this.devices.observe({ mac: n.mac, ip: n.ip, ts: now, isLocal: true })
      }
    } catch (err) {
      this.log.debug(SCOPE, `Neighbour refresh failed: ${String(err)}`)
    }
  }
}
