import { useState } from 'react'
import { Layout, type PageId } from './components/Layout'
import { AlertsPage } from './pages/Alerts'
import { AnalyticsPage } from './pages/Analytics'
import { ConnectionsPage } from './pages/Connections'
import { DashboardPage } from './pages/Dashboard'
import { DevicesPage } from './pages/Devices'
import { DnsPage } from './pages/Dns'
import { LiveTrafficPage } from './pages/LiveTraffic'
import { LogsPage } from './pages/Logs'
import { PacketCapturePage } from './pages/PacketCapture'
import { ProtocolsPage } from './pages/Protocols'
import { RouterControlPage } from './pages/RouterControl'
import { SettingsPage } from './pages/Settings'
import { TlsPage, UnencryptedPage } from './pages/Unencrypted'
import { useApp } from './state'

export function App(): React.JSX.Element {
  const [page, setPage] = useState<PageId>('dashboard')
  const { ready } = useApp()

  if (!ready) {
    return (
      <div className="grid h-full w-full place-items-center bg-bg text-muted">
        <div className="flex flex-col items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-accent text-lg font-bold text-[#04121c]">
            b
          </div>
          <span className="text-sm">blazma.nt</span>
        </div>
      </div>
    )
  }

  return (
    <Layout page={page} onNavigate={setPage}>
      {page === 'dashboard' && <DashboardPage onNavigate={setPage} />}
      {page === 'devices' && <DevicesPage />}
      {page === 'live' && <LiveTrafficPage />}
      {page === 'connections' && <ConnectionsPage />}
      {page === 'protocols' && <ProtocolsPage />}
      {page === 'dns' && <DnsPage />}
      {page === 'unencrypted' && <UnencryptedPage />}
      {page === 'tls' && <TlsPage />}
      {page === 'alerts' && <AlertsPage />}
      {page === 'analytics' && <AnalyticsPage />}
      {page === 'router' && <RouterControlPage />}
      {page === 'pcap' && <PacketCapturePage />}
      {page === 'logs' && <LogsPage />}
      {page === 'settings' && <SettingsPage />}
    </Layout>
  )
}
