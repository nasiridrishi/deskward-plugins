/** What the last status read of the project's Deskward target said. */
export type Snapshot = {
  /** When it was read, in milliseconds since the epoch. */
  at: number
  /** Why the target could not be read; the rest is absent then. */
  error?: string
  target?: string
  host?: string
  backend?: string
  guardsReady?: boolean
  guardError?: string
  desktopAvailable?: boolean
  paused?: boolean
  pauseReason?: string
  stopFile?: boolean
  idleSeconds?: number
  session?: {
    active: boolean
    state: string
    label?: string
    requester?: string
    approved: boolean
    approvedUntil?: string
    viewOnly: boolean
    extension?: { minutes: number; reason: string }
  }
}

/** One Deskward tool call of the agent's, as the pane lists it. */
export type Action = {
  id: string
  at: number
  tool: string
  /** `running`, `ok`, or the error code the target or companion answered with. */
  outcome: string
}

/** Something Deskward drew on a screenshot, in physical screen pixels. */
export type Mark = {
  kind: 'click' | 'drag' | 'move' | 'scroll' | 'found'
  at?: [number, number]
  from?: [number, number]
  to?: [number, number]
  box?: [number, number, number, number]
}

/** One of the agent's screenshots, as the pane replays it. */
export type Frame = {
  id: string
  at: number
  /** Deskward's small JPEG copy, base64, with the marks already drawn on it; absent if none came. */
  jpeg?: string
  /** The part of the screen shown, [x, y, width, height] in physical pixels. */
  region: [number, number, number, number]
  marks: Mark[]
  /** The window the agent's input goes to. */
  window?: [number, number, number, number]
  /** The agent's other Deskward calls since its previous screenshot, oldest first. */
  steps: { tool: string; outcome: string }[]
}

declare module 'claude-code' {
  interface PluginState {
    'deskward-panel': {
      status: Shaped<Snapshot | null>
      actions: Shaped<Action[]>
      now: Shaped<number>
      frames: Shaped<Frame[]>
      /** Which frame the pane shows: an index into frames, or null for the latest. */
      shown: Shaped<number | null>
    }
  }
}
