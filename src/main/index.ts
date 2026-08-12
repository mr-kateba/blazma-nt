import { join } from 'node:path'
import { app, BrowserWindow, shell } from 'electron'
import { EventBus } from '../backend/core/bus.js'
import { Engine } from '../backend/core/engine.js'
import { SettingsManager } from '../backend/core/settings.js'
import { Store } from '../backend/database/store.js'
import { RouterManager } from '../backend/router/manager.js'
import { Logger } from '../backend/utils/logger.js'
import { registerIpc } from './ipc.js'

const SCOPE = 'main'

let window: BrowserWindow | null = null
let store: Store | null = null
let engine: Engine | null = null
let disposeIpc: (() => void) | null = null

// A second instance would fight over the database and the capture handle.
if (!app.requestSingleInstanceLock()) {
  app.quit()
}

function createWindow(): BrowserWindow {
  const win = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1100,
    minHeight: 680,
    show: false,
    autoHideMenuBar: true,
    backgroundColor: '#0b0f17',
    title: 'blazma.nt',
    webPreferences: {
      preload: join(import.meta.dirname, '../preload/index.mjs'),
      // Security baseline: the renderer is a plain web page with no Node access
      // and no direct access to Electron APIs. Everything goes through the
      // allowlisted preload bridge.
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      experimentalFeatures: false
    }
  })

  win.once('ready-to-show', () => win.show())

  // External links open in the user's browser, never inside the app.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) void shell.openExternal(url)
    return { action: 'deny' }
  })
  win.webContents.on('will-navigate', (event, url) => {
    const isDev = Boolean(process.env.ELECTRON_RENDERER_URL)
    if (isDev && url.startsWith(process.env.ELECTRON_RENDERER_URL as string)) return
    event.preventDefault()
  })

  if (process.env.ELECTRON_RENDERER_URL) {
    void win.loadURL(process.env.ELECTRON_RENDERER_URL)
  } else {
    void win.loadFile(join(import.meta.dirname, '../renderer/index.html'))
  }

  return win
}

app.whenReady().then(() => {
  const dbPath = join(app.getPath('userData'), 'blazma.db')
  store = new Store(dbPath)

  const bus = new EventBus()
  const settings = new SettingsManager(store)
  const log = new Logger(store, bus)
  log.setLevel(settings.get().logLevel)
  log.info(SCOPE, `blazma.nt started. Database: ${dbPath} (driver: ${store.db.driver})`)

  engine = new Engine(store, bus, settings, log)
  const router = new RouterManager(bus, log)

  disposeIpc = registerIpc({
    store,
    bus,
    engine,
    settings,
    router,
    log,
    getWindow: () => (window && !window.isDestroyed() ? window : null)
  })

  // Detect the router in the background and try to restore a saved session.
  void router
    .detect()
    .then(() => router.reconnect())
    .catch(() => undefined)

  // Trim anything older than the retention policy at startup.
  const removed = store.applyRetention(settings.get().retention)
  if (removed > 0) log.info(SCOPE, `Retention removed ${removed} rows at startup.`)

  window = createWindow()

  app.on('second-instance', () => {
    if (!window) return
    if (window.isMinimized()) window.restore()
    window.focus()
  })

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) window = createWindow()
  })
})

app.on('window-all-closed', () => {
  app.quit()
})

app.on('before-quit', async (event) => {
  if (!engine) return
  const running = engine.getStatus().state
  if (running === 'stopped') return
  // Stop capture cleanly so the child process never outlives the app.
  event.preventDefault()
  const current = engine
  engine = null
  await current.shutdown()
  app.quit()
})

app.on('quit', () => {
  disposeIpc?.()
  store?.close()
})

process.on('uncaughtException', (err) => {
  console.error('[fatal] uncaught exception:', err)
})
process.on('unhandledRejection', (reason) => {
  console.error('[fatal] unhandled rejection:', reason)
})
