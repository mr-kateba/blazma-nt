import type { ApiChannel, ApiMap } from '@shared/ipc'
import type { EventChannel, EventMap } from '@shared/types'

interface Bridge {
  invoke<C extends ApiChannel>(channel: C, payload?: ApiMap[C]['req']): Promise<ApiMap[C]['res']>
  on<C extends EventChannel>(channel: C, listener: (payload: EventMap[C]) => void): () => void
}

declare global {
  interface Window {
    blazma: Bridge
  }
}

/** Typed access to the backend. Throws with the backend's message on failure. */
export const api = {
  invoke: <C extends ApiChannel>(channel: C, payload?: ApiMap[C]['req']): Promise<ApiMap[C]['res']> =>
    window.blazma.invoke(channel, payload),
  on: <C extends EventChannel>(channel: C, listener: (payload: EventMap[C]) => void): (() => void) =>
    window.blazma.on(channel, listener)
}

/** Normalises the Error thrown across IPC into a displayable string. */
export function errorMessage(err: unknown): string {
  if (err instanceof Error) {
    // Electron prefixes IPC errors with "Error invoking remote method '...':".
    return err.message.replace(/^Error invoking remote method '[^']+':\s*(Error:\s*)?/, '')
  }
  return String(err)
}
