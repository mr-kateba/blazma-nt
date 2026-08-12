import { contextBridge, ipcRenderer } from 'electron'
import { API_CHANNELS, EVENT_CHANNELS, type ApiChannel, type ApiMap } from '../shared/ipc.js'
import type { EventChannel, EventMap } from '../shared/types.js'

const apiChannels = new Set<string>(API_CHANNELS)
const eventChannels = new Set<string>(EVENT_CHANNELS)

/**
 * The only bridge between the UI and the backend. Both directions are
 * allowlisted by channel name — the renderer cannot reach an arbitrary
 * ipcMain handler, and cannot subscribe to an arbitrary event.
 */
const bridge = {
  invoke<C extends ApiChannel>(channel: C, payload?: ApiMap[C]['req']): Promise<ApiMap[C]['res']> {
    if (!apiChannels.has(channel)) {
      return Promise.reject(new Error(`blocked ipc channel: ${String(channel)}`))
    }
    return ipcRenderer.invoke(channel, payload) as Promise<ApiMap[C]['res']>
  },

  on<C extends EventChannel>(channel: C, listener: (payload: EventMap[C]) => void): () => void {
    if (!eventChannels.has(channel)) {
      throw new Error(`blocked event channel: ${String(channel)}`)
    }
    const wrapped = (_e: unknown, payload: EventMap[C]): void => listener(payload)
    ipcRenderer.on(channel, wrapped)
    return () => ipcRenderer.removeListener(channel, wrapped)
  }
}

export type Bridge = typeof bridge

contextBridge.exposeInMainWorld('blazma', bridge)
