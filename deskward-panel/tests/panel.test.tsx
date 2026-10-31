import { expect, mock, test } from 'claude-code/testing'
import type { On } from 'claude-code'

const START = Date.parse('2026-10-31T10:00:00Z')

const PANE = {
  plugin: 'deskward-panel',
  component: 'Pane',
  requestId: 'deskward',
  props: {
    title: 'Deskward',
    isFocused: false,
    bodyColumns: 48,
    placement: 'dock',
    scroll: { offset: 0, bodyRows: 30 },
    view: {},
  },
} as const

/** A status reply as deskward-mcp gives it to a caller with no session key. */
function status(work: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  return {
    target: 'office',
    host: 'OFFICE-PC',
    backend: 'windows',
    hooks_ready: true,
    hook_error: null,
    desktop_available: true,
    paused: false,
    stop_file: false,
    user_idle_seconds: 42,
    overlay: {},
    work_session: { active: false, state: 'Idle', approved: false, ...work },
    ...extra,
  }
}

/** The engine beneath the mod: its commands and pane, and a deskward server answering `reply`. */
function engine(on: On, reply: () => unknown) {
  on('command.register', () => ({ value: { command: 'deskward' } }))
  on('ui.open', () => ({ value: { isPlaced: true } }))
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('mcp.call', () => ({ value: { content: [{ type: 'text', text: JSON.stringify(reply()) }], isError: false } }))
}

async function texts(ui: { find: (q: { type: 'Text'; text: RegExp }) => Promise<{ text?: string } | undefined> }, pattern: RegExp) {
  return (await ui.find({ type: 'Text', text: pattern }))?.text
}

test('an approved session shows its time left, which counts down', async ($, on) => {
  const clock = mock.clock(on, { now: START })
  engine(on, () =>
    status({ active: true, state: 'Using screen', approved: true, label: 'Run the KQL query', approved_until: new Date(START + 3600_000).toISOString() }),
  )
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  await clock.settle()

  for (const surface of ['desktop', 'terminal'] as const) {
    const ui = await $.ui.mount({ ...PANE, surface })
    expect(await texts(ui, /^Approved$/)).toBe('Approved')
    expect(await texts(ui, /left$/)).toBe('1h 00m left')
    expect(await texts(ui, /OFFICE-PC/)).toBe('office  ·  OFFICE-PC')
    expect(await texts(ui, /^Task/)).toBe('Task: Run the KQL query')
    expect(await texts(ui, /^Person/)).toBe('Person: away for 42s')
    await ui.unmount()
  }

  await clock.advance(10 * 60_000)
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  expect(await texts(ui, /left$/)).toBe('50m 00s left')
  await ui.unmount()
})

test('a pending request, a pause and someone at the computer say so', async ($, on) => {
  const clock = mock.clock(on, { now: START })
  let reply: unknown = status({ active: true, state: 'Awaiting approval', approved: false })
  engine(on, () => reply)
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  await clock.settle()

  let ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  expect(await texts(ui, /^Waiting/)).toBe('Waiting for approval')
  await ui.unmount()

  reply = status({ active: true, state: 'Paused', approved: true }, { paused: true, user_idle_seconds: 1, overlay: { pause_reason: 'Paused' } })
  await clock.advance(5000)
  ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  expect(await texts(ui, /^Paused$/)).toBe('Paused')
  expect(await texts(ui, /^Person/)).toBe('Person: using the computer now')
  await ui.unmount()
})

test('the agent’s Deskward calls are listed, refusals by their code, other tools not at all', async ($, on) => {
  const clock = mock.clock(on, { now: START })
  engine(on, () => status({}))
  on('tool.call', (_, e) =>
    e.tool === 'mcp__deskward__key'
      ? { result: {}, isError: true, text: '{"code":"observe_before_submit","message":"Take a screenshot first"}' }
      : { result: {}, text: '{"ok":true}' },
  )
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  await clock.settle()

  await $.tool.call({ tool: 'mcp__deskward__screenshot' })
  await $.tool.call({ tool: 'mcp__deskward__key', chord: 'Return' })
  await $.tool.call({ tool: 'Bash', command: 'ls' })

  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  expect(await texts(ui, /key/)).toMatch(/key {2}observe_before_submit$/)
  expect(await texts(ui, /screenshot/)).toMatch(/screenshot {2}$/)
  expect(await ui.find({ type: 'Text', text: /Bash/ })).toBeUndefined()
  await ui.unmount()
})

test('the agent’s screenshots are replayed with what it did between them', async ($, on) => {
  const clock = mock.clock(on, { now: START })
  engine(on, () => status({}))
  const asked: Record<string, unknown>[] = []
  let shots = 0
  on('tool.call', (_, e) => {
    asked.push({ ...e })
    if (e.tool !== 'mcp__deskward__screenshot') return { result: {}, text: '{"clicked":[900,300]}' }
    shots += 1
    if (e.forged === 'region') {
      const text = JSON.stringify({ region: [0, 0, '1920" onload="evil()', 1080], preview: { block: 2 } })
      return { result: [{ type: 'text', text }], text }
    }
    if (e.forged) {
      const text = JSON.stringify({
        region: [0, 0, 1920, 1080],
        marks: { drawn: [{ kind: 'click', at: ['1"/><script>evil()</script>', 2] }, { kind: 'found', box: [1, 2, 3, 4] }] },
        preview: { block: 2 },
      })
      return { result: [{ type: 'text', text }, {}, { type: 'image', data: 'AAAA"/><script>evil()</script>' }], text }
    }
    const reply = {
      region: [0, 0, 1920, 1080],
      marks: shots === 2 ? { drawn: [{ kind: 'click', at: [900, 300] }], window: [100, 100, 800, 600] } : undefined,
      preview: { block: 2, image_size: [480, 270] },
    }
    const text = JSON.stringify(reply)
    return {
      result: [
        { type: 'text', text },
        { type: 'image', data: 'FULL', mimeType: 'image/png' },
        { type: 'image', data: `SMALL${shots}`, mimeType: 'image/jpeg' },
      ],
      text,
    }
  })
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  await clock.settle()

  await $.tool.call({ tool: 'mcp__deskward__screenshot' })
  await clock.advance(1000)
  await $.tool.call({ tool: 'mcp__deskward__click', x: 900, y: 300 })
  await clock.advance(1000)
  await $.tool.call({ tool: 'mcp__deskward__screenshot', scale: 0.5 })
  expect(asked.filter(a => a.tool === 'mcp__deskward__screenshot').map(a => a.preview)).toEqual([true, true])
  expect(asked.find(a => a.tool === 'mcp__deskward__click')?.preview).toBeUndefined()

  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  const svg = await ui.find({ type: 'Svg' })
  expect(String(svg?.props.source)).toContain('data:image/jpeg;base64,SMALL2')
  expect(String(svg?.props.source)).toContain('<circle cx="900" cy="300"')
  expect(await texts(ui, /^Since the last look/)).toBe('Since the last look: clicked 900, 300')
  expect(await texts(ui, /^click$/)).toBe('click')
  expect(await texts(ui, /^Screen at/)).toMatch(/2 of 2$/)

  await ui.press({ key: 'back' })
  expect(String((await ui.find({ type: 'Svg' }))?.props.source)).toContain('SMALL1')
  expect(await texts(ui, /^Screen at/)).toMatch(/1 of 2$/)
  expect(await texts(ui, /^Nothing done/)).toBe('Nothing done since the last look')
  await ui.press({ key: 'latest' })
  expect(await texts(ui, /^Screen at/)).toMatch(/2 of 2$/)

  await $.tool.call({ tool: 'mcp__deskward__screenshot', forged: true })
  const forged = String((await ui.find({ type: 'Svg' }))?.props.source)
  expect(forged).not.toContain('onload')
  expect(forged).not.toContain('evil')
  expect(forged).not.toContain('<script')
  expect(forged).not.toContain('data:image')
  expect(forged).toContain('<rect x="1" y="2" width="3" height="4"')
  await $.tool.call({ tool: 'mcp__deskward__screenshot', forged: 'region' })
  expect(await texts(ui, /^Screen at/)).toMatch(/3 of 3$/)
  await ui.unmount()

  const terminal = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await terminal.find({ type: 'Svg' })).toBeUndefined()
  expect(await texts(terminal, /^Since the last look/)).toBe('Since the last look: found text')
  await terminal.unmount()
})

test('a project with no deskward server shows it as unreachable and opens no pane', async ($, on) => {
  const clock = mock.clock(on, { now: START })
  let opened = 0
  on('command.register', () => ({ value: { command: 'deskward' } }))
  on('ui.open', () => {
    opened += 1
    return { value: { isPlaced: true } }
  })
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('mcp.call', () => {
    throw new Error('No MCP server named deskward')
  })
  await $.session.start({ cwd: '/', surface: 'desktop', isInteractive: true })
  await clock.settle()

  expect(opened).toBe(0)
  const ui = await $.ui.mount({ ...PANE, surface: 'desktop' })
  expect(await texts(ui, /^Unreachable$/)).toBe('Unreachable')
  await ui.unmount()
})
