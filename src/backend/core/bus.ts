import type { EventChannel, EventMap } from '../../shared/types.js'

type Listener<C extends EventChannel> = (payload: EventMap[C]) => void

/**
 * Typed in-process event bus. The engine publishes here; the IPC layer is the
 * only subscriber that forwards to the renderer, so backend modules never hold
 * a reference to a BrowserWindow.
 */
export class EventBus {
  private listeners = new Map<EventChannel, Set<Listener<EventChannel>>>()

  on<C extends EventChannel>(channel: C, listener: Listener<C>): () => void {
    let set = this.listeners.get(channel)
    if (!set) {
      set = new Set()
      this.listeners.set(channel, set)
    }
    set.add(listener as Listener<EventChannel>)
    return () => void set.delete(listener as Listener<EventChannel>)
  }

  emit<C extends EventChannel>(channel: C, payload: EventMap[C]): void {
    const set = this.listeners.get(channel)
    if (!set) return
    for (const listener of set) {
      try {
        ;(listener as Listener<C>)(payload)
      } catch {
        // A failing UI listener must never take down the capture pipeline.
      }
    }
  }
}
