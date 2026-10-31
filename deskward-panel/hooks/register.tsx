import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { Action, Frame, Mark, Snapshot } from '../types'

const PANE = 'deskward'
const SERVER = 'deskward'
const PREFIX = `mcp__${SERVER}__`
/** How often the target is asked while it answers, and while it does not. */
const POLL_MS = 5000
const RETRY_MS = 60000
const KEPT_ACTIONS = 40
/** Screenshots kept to step back through; each is a small JPEG of some tens of kilobytes. */
const KEPT_FRAMES = 8
/** Width the replayed screen is drawn at, and the most markup the desktop's Svg element takes. */
const FRAME_WIDTH = 480
const SVG_LIMIT = 131_072
/** An approval this far off is the person's "no time limit". */
const NO_LIMIT_MS = 365 * 24 * 3600 * 1000
/** Deskward's direct connection: HTTPS for MCP, and plain HTTP that serves only its certificate. */
const DIRECT_PORT = 47391

// Change a tag when that value's fields change: it declines what an earlier version stored.
const status = atom({ plugin: 'deskward-panel', key: 'status' } as const, null, { shape: 'status-1' })
const actions = atom({ plugin: 'deskward-panel', key: 'actions' } as const, [], { shape: 'actions-1' })
const now = atom({ plugin: 'deskward-panel', key: 'now' } as const, 0, { shape: 'now-1' })
const frames = atom({ plugin: 'deskward-panel', key: 'frames' } as const, [], { shape: 'frames-1' })
const shown = atom({ plugin: 'deskward-panel', key: 'shown' } as const, null, { shape: 'shown-1' })

/** The first JSON object in a tool's text, which the companion writes as its reply or error. */
function json(text: string | undefined): Record<string, any> | undefined {
  if (!text) return undefined
  const start = text.indexOf('{')
  const end = text.lastIndexOf('}')
  if (start < 0 || end <= start) return undefined
  try {
    return JSON.parse(text.slice(start, end + 1))
  } catch {
    return undefined
  }
}

/** Reads status the way any caller without a session key may: no screen, no key, no binding. */
function snapshot(at: number, reply: Record<string, any> | undefined, error?: string): Snapshot {
  if (!reply) return { at, error: error ?? 'Deskward did not answer' }
  const work = reply.work_session ?? {}
  const extension = work.extension_request
  return {
    at,
    target: reply.target ?? undefined,
    host: reply.host ?? undefined,
    backend: reply.backend ?? undefined,
    guardsReady: reply.hooks_ready === true,
    guardError: reply.hook_error ?? undefined,
    desktopAvailable: reply.desktop_available === true,
    paused: reply.paused === true,
    pauseReason: reply.overlay?.pause_reason ?? undefined,
    stopFile: reply.stop_file === true,
    idleSeconds: typeof reply.user_idle_seconds === 'number' ? reply.user_idle_seconds : undefined,
    session: {
      active: work.active === true,
      state: String(work.state ?? 'Idle'),
      label: work.label ?? undefined,
      requester: work.requester ?? undefined,
      approved: work.approved === true,
      approvedUntil: work.approved_until ?? undefined,
      viewOnly: work.preferences?.observe_only === true,
      extension: extension ? { minutes: extension.minutes, reason: extension.reason } : undefined,
    },
  }
}

/**
 * The address to reach a computer by: a bare computer name gets `.local`, which Deskward's
 * certificate names and which survives an address change. Undefined for anything that is not a
 * host name or address, so nothing else reaches a URL or a command.
 */
export function address(name: string): string | undefined {
  const host = name.trim().toLowerCase()
  if (!host || host.length > 253 || !/^[a-z0-9.\-:\[\]]+$/.test(host)) return undefined
  return host.includes('.') || host.includes(':') ? host : `${host}.local`
}

/** Exactly one PEM certificate and nothing around it but white space. */
export function onePem(text: string): boolean {
  const body = text.trim()
  return (
    body.startsWith('-----BEGIN CERTIFICATE-----') &&
    body.endsWith('-----END CERTIFICATE-----') &&
    body.split('-----BEGIN').length === 2 &&
    body.split('-----END').length === 2
  )
}

const MANUAL = (host: string) =>
  [
    `Open http://${host}:${DIRECT_PORT}/ and download the certificate.`,
    `Check its SHA-256 against direct/authority-fingerprint.txt in Deskward's data folder on ${host}.`,
    'Trust it for websites in the system certificate store, then:',
    `claude mcp add -s local -t http ${SERVER} https://${host}:${DIRECT_PORT}/mcp`,
    `claude mcp login ${SERVER}`,
  ].join('\n')

/*
 * SPAKE2 keyed by the pairing code, as Deskward runs it (crates/deskward-companion/src/direct/pake.rs):
 * the 2048-bit MODP group of RFC 3526, generator 2, blinding elements M and N made from hashes.
 * Someone in between who does not know the code can neither read the key nor test a guess
 * without spending the code. Each number is 256 bytes big-endian on the wire.
 */
const PRIME = BigInt(
  '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F2411' +
    '7C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497C' +
    'EA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',
)
const ORDER = (PRIME - 1n) / 2n
const ELEMENT = 256
const utf8 = (text: string) => new TextEncoder().encode(text)

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

function fromHex(text: string): Uint8Array | undefined {
  if (!/^(?:[0-9a-f]{2})*$/.test(text)) return undefined
  return Uint8Array.from(text.match(/../g) ?? [], pair => parseInt(pair, 16))
}

function toBig(bytes: Uint8Array): bigint {
  return bytes.length ? BigInt(`0x${hex(bytes)}`) : 0n
}

export function toBytes(n: bigint): Uint8Array {
  return fromHex(n.toString(16).padStart(ELEMENT * 2, '0'))!
}

export function power(base: bigint, exponent: bigint, modulus = PRIME): bigint {
  let result = 1n
  let b = base % modulus
  for (let e = exponent; e > 0n; e >>= 1n) {
    if (e & 1n) result = (result * b) % modulus
    b = (b * b) % modulus
  }
  return result
}

export async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const joined = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const part of parts) {
    joined.set(part, at)
    at += part.length
  }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', joined))
}

/** Each part preceded by its length as eight bytes, as Deskward frames them. */
function framed(parts: Uint8Array[]): Uint8Array[] {
  return parts.flatMap(part => {
    const length = new Uint8Array(8)
    new DataView(length.buffer).setBigUint64(0, BigInt(part.length))
    return [length, part]
  })
}

/** HMAC-SHA256 over framed parts, with a key of at most 64 bytes. */
export async function mac(key: Uint8Array, parts: Uint8Array[]): Promise<Uint8Array> {
  const block = new Uint8Array(64)
  block.set(key)
  const pad = (byte: number) => block.map(b => b ^ byte)
  const inner = await sha256(pad(0x36), ...framed(parts))
  return sha256(pad(0x5c), inner)
}

/** 256 bytes from SHA-256 of the label and a counter byte, squared into the subgroup. */
export async function blinding(label: string): Promise<bigint> {
  const blocks = await Promise.all(Array.from({ length: 8 }, (_, i) => sha256(utf8(label), Uint8Array.of(i))))
  return power(toBig(new Uint8Array(blocks.flatMap(b => Array.from(b)))), 2n)
}

export async function secret(code: string): Promise<bigint> {
  return toBig(await sha256(utf8(`deskward spake2 w ${code}`))) % ORDER
}

/** Deskward's Y, if it is an element of the subgroup. */
function element(text: unknown): bigint | undefined {
  const bytes = typeof text === 'string' ? fromHex(text) : undefined
  if (!bytes || bytes.length !== ELEMENT) return undefined
  const y = toBig(bytes)
  return y > 1n && y < PRIME - 1n && power(y, ORDER) === 1n ? y : undefined
}

/** The client's half: X from its exponent, then the key from Deskward's Y. */
export async function spake(code: string, x: bigint) {
  const [m, n, w] = [await blinding('deskward spake2 M'), await blinding('deskward spake2 N'), await secret(code)]
  const blinded = (power(2n, x) * power(m, w)) % PRIME
  return {
    blinded,
    key: async (y: bigint) => {
      const shared = power((y * power(n, ORDER - w)) % PRIME, x)
      const parts = [utf8('deskward spake2 v1'), toBytes(blinded), toBytes(y), toBytes(shared), toBytes(w)]
      return sha256(...framed(parts))
    },
  }
}

/** One DER element: its tag and where its contents lie. */
type Tlv = { tag: number; start: number; end: number }

function tlv(der: Uint8Array, at: number, limit = der.length): Tlv | undefined {
  if (at + 2 > limit) return undefined
  const tag = der[at]!
  let length = der[at + 1]!
  let start = at + 2
  if (length & 0x80) {
    const count = length & 0x7f
    if (count < 1 || count > 3 || start + count > limit) return undefined
    length = 0
    for (let i = 0; i < count; i++) length = length * 256 + der[start + i]!
    start += count
  }
  return start + length <= limit ? { tag, start, end: start + length } : undefined
}

/** The elements inside a constructed one. */
function children(der: Uint8Array, parent: Tlv): Tlv[] | undefined {
  const out: Tlv[] = []
  for (let at = parent.start; at < parent.end; ) {
    const child = tlv(der, at, parent.end)
    if (!child) return undefined
    out.push(child)
    at = child.end
  }
  return out
}

const BASIC_CONSTRAINTS = '551d13'
const NAME_CONSTRAINTS = '551d1e'
const KEY_USAGE = '551d0f'

/**
 * Whether a certificate, read from its DER, is the kind of authority Deskward makes: a critical
 * CA:TRUE, and critical name constraints that permit only `local` and `localhost` and exclude
 * every IPv4 and IPv6 address and nothing else, with no other critical extension. A Deskward that is not what it claims, but knew the
 * code, must not get an authority that can vouch for any site into the keychain.
 */
export function constrainedAuthority(der: Uint8Array): boolean {
  const certificate = tlv(der, 0)
  const tbs = certificate && children(der, certificate)?.[0]
  const fields = tbs && children(der, tbs)
  const extensions = fields?.find(f => f.tag === 0xa3)
  const list = extensions && children(der, extensions)?.[0]
  const entries = list && children(der, list)
  if (!entries) return false
  let basic = false
  let names = false
  for (const entry of entries) {
    const parts = children(der, entry)
    if (!parts || parts.length < 2 || parts[0]!.tag !== 0x06) return false
    const oid = hex(der.subarray(parts[0]!.start, parts[0]!.end))
    const critical = parts.length === 3 && parts[1]!.tag === 0x01 && der[parts[1]!.start] === 0xff
    const value = parts[parts.length - 1]!
    if (value.tag !== 0x04) return false
    const inner = tlv(der, value.start, value.end)
    if (oid === BASIC_CONSTRAINTS) {
      const flags = inner && children(der, inner)
      const ca = flags?.[0]
      if (basic || !critical || !ca || ca.tag !== 0x01 || der[ca.start] !== 0xff) return false
      basic = true
    } else if (oid === NAME_CONSTRAINTS) {
      const subtrees = inner && children(der, inner)
      if (names || !critical || !subtrees || subtrees.length !== 2) return false
      if (subtrees[0]!.tag !== 0xa0 || subtrees[1]!.tag !== 0xa1) return false
      // Excluded: exactly every IPv4 and every IPv6 address, as an iPAddress of all zeros.
      const excluded = (children(der, subtrees[1]!) ?? []).map(tree => children(der, tree)?.[0])
      const everything = (bytes: number) =>
        excluded.some(b => b?.tag === 0x87 && b.end - b.start === bytes && der.subarray(b.start, b.end).every(x => x === 0))
      if (excluded.length !== 2 || !everything(8) || !everything(32)) return false
      const permitted = children(der, subtrees[0]!) ?? []
      const allowed = permitted.map(tree => {
        const base = children(der, tree)?.[0]
        return base?.tag === 0x82 ? new TextDecoder().decode(der.subarray(base.start, base.end)) : undefined
      })
      if (!allowed.includes('local') || !allowed.every(name => name === 'local' || name === 'localhost')) return false
      names = true
    } else if (critical && oid !== KEY_USAGE) {
      return false
    }
  }
  return basic && names
}

function randomExponent(): bigint {
  return (toBig(crypto.getRandomValues(new Uint8Array(ELEMENT))) % (ORDER - 1n)) + 1n
}

function pemToDer(pem: string): Uint8Array {
  const body = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
  return Uint8Array.from(atob(body), c => c.charCodeAt(0))
}

const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i])

type Reply = { ok: boolean; status: number; body: Record<string, any> }

async function post($: EngineInterface, url: string, body: unknown): Promise<Reply> {
  const r = await $.http.fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  return { ok: r.ok, status: r.status, body: JSON.parse(r.text || '{}') }
}

/**
 * `/deskward connect <computer> [code]`: pairs this project with that computer's Deskward by the
 * code its panel shows and the person's Confirm there, then trusts its certificate and adds it as
 * the `deskward` server. The code proves the certificate came from that Deskward, so there is
 * nothing to compare; the token this computer presents is made here and never sent, only its hash.
 */
async function connect($: EngineInterface, name: string, given?: string): Promise<string> {
  const host = address(name)
  if (!host) return 'Usage: /deskward connect <computer>, for example /deskward connect office-pc'
  const platform = await $.process.run(['uname', '-s']).then(
    r => r.stdout.trim(),
    () => 'unknown',
  )
  if (platform !== 'Darwin') return `Automatic setup is built for macOS only so far. On this computer:\n${MANUAL(host)}`

  const typed =
    given ??
    (await $.ui
      .ask(`On ${host}, open Deskward's menu, choose Other computers, then Pair a computer. Type the code it shows.`, {
        options: ['Cancel', 'Not now'],
        header: 'Pairing code',
      })
      .catch(() => 'Cancel'))
  const code = typed.replace(/\s+/g, '')
  if (!/^\d{6}$/.test(code)) {
    return /^(Cancel|Not now)$/.test(typed) ? 'Nothing was changed.' : 'That is not a six-digit code. Nothing was changed.'
  }
  const computer =
    (await $.process.run(['scutil', '--get', 'ComputerName']).then(
      r => r.stdout.trim(),
      () => '',
    )) || 'Mac'

  const base = `http://${host}:${DIRECT_PORT}`
  const ours = await spake(code, randomExponent())
  const started = await post($, `${base}/pair/start`, { x: hex(toBytes(ours.blinded)), name: computer }).catch(() => undefined)
  if (!started) return `No Deskward answered at ${host}:${DIRECT_PORT}. On that computer, turn on Allow agents on other computers in Deskward's menu, and check the name.`
  if (!started.ok) return `${host} refused: ${started.body.message ?? `status ${started.status}`}. Nothing was changed.`
  const y = element(started.body.y)
  const pem = String(started.body.certificate ?? '')
  if (!y || !onePem(pem)) return `What ${host} sent is not a Deskward exchange. Nothing was changed.`
  const key = await ours.key(y)
  const der = pemToDer(pem)
  const derHash = await sha256(der)
  if (hex(await mac(key, [utf8('target'), derHash])) !== started.body.confirm) {
    return `The code did not match: it was mistyped, or something other than Deskward answered for ${host}. Nothing was trusted; press Pair a computer there for a new code.`
  }
  if (!constrainedAuthority(der)) {
    return `${host} sent a certificate authority that is not limited to .local names and closed to addresses, which Deskward never makes. Nothing was trusted; press Pair a computer there to cancel.`
  }

  const token = hex(crypto.getRandomValues(new Uint8Array(32)))
  const tokenHash = hex(await sha256(utf8(token)))
  const proof = hex(await mac(key, [utf8('client'), utf8(tokenHash)]))
  const finished = await post($, `${base}/pair/finish`, { id: started.body.id, token_hash: tokenHash, confirm: proof }).catch(() => undefined)
  if (!finished?.ok) return `${host} refused: ${finished?.body.message ?? 'no answer'}. Nothing was changed.`
  // A headless run has nowhere to show it; the wait goes on either way.
  try {
    $.ui.toast(`Press Confirm on ${host}`, { timeoutMs: 15_000 })
  } catch {
    // Nothing to show it on.
  }
  // Deskward holds each request until the person answers, up to 20 seconds, so the wait is spent
  // on the network and not out of this command's own time; Confirm is open for two minutes.
  let answer: Record<string, any> | undefined
  for (let i = 0; i < 8 && !answer; i++) {
    const r = await $.http.fetch(`${base}/pair/result?id=${encodeURIComponent(String(started.body.id))}`).catch(() => undefined)
    const body = r?.ok ? JSON.parse(r.text) : undefined
    if (!body) break
    if (body.waiting !== true) answer = body
  }
  if (answer?.paired !== true) return `${host} was not paired: Confirm was not pressed there. Nothing was changed.`
  if (hex(await mac(key, [utf8('paired'), utf8(tokenHash)])) !== answer.confirm) {
    return `${host}'s answer did not check out. Nothing was trusted; remove this computer on ${host}'s panel.`
  }

  // Trust exactly the certificate the code vouched for: re-encoded by openssl and checked again.
  const folder = (await $.process.run(['mktemp', '-d', '-t', 'deskward'])).stdout.trim()
  const pemFile = `${folder}/served.pem`
  const derFile = `${folder}/deskward-ca.cer`
  try {
    await $.fs.write(pemFile, pem)
    await $.process.run(['/usr/bin/openssl', 'x509', '-in', pemFile, '-outform', 'DER', '-out', derFile])
    const read = await $.process.run(['/usr/bin/openssl', 'x509', '-inform', 'DER', '-in', derFile, '-noout', '-fingerprint', '-sha256'])
    const written = read.stdout.match(/Fingerprint=([0-9A-Fa-f:]+)/)?.[1]?.replaceAll(':', '').toLowerCase()
    if (read.exitCode !== 0 || written !== hex(derHash)) {
      return `The certificate changed on its way to the keychain, so nothing was trusted. ${host} is paired; remove it there if you do not try again.`
    }
    const trusted = await $.process.run(['security', 'add-trusted-cert', '-r', 'trustRoot', '-p', 'ssl', derFile], {
      timeoutMs: 300_000,
    })
    if (trusted.exitCode !== 0) {
      return `macOS did not add the trust (${trusted.stderr.trim() || `exit ${trusted.exitCode}`}). ${host} is paired; run this again to finish.`
    }
  } finally {
    await $.process.run(['rm', '-f', pemFile, derFile]).catch(() => undefined)
    await $.process.run(['rmdir', folder]).catch(() => undefined)
  }

  const url = `https://${host}:${DIRECT_PORT}/mcp`
  const cwd = await $.session.cwd()
  const add = () =>
    $.process.run(['claude', 'mcp', 'add', '-s', 'local', '-t', 'http', SERVER, url, '-H', `Authorization: Bearer ${token}`], { cwd })
  let added = await add().catch(() => undefined)
  if (added && added.exitCode !== 0 && /already exists/i.test(added.stdout + added.stderr)) {
    const replace = await $.ui.ask(`This project already has an MCP server named ${SERVER}. Replace it with Deskward on ${host}?`, {
      options: ['Replace it', 'Keep it'],
      header: 'Server',
    })
    if (replace !== 'Replace it') return `${host} is paired and trusted, but the project's ${SERVER} server was kept.`
    await $.process.run(['claude', 'mcp', 'remove', '-s', 'local', SERVER], { cwd })
    added = await add().catch(() => undefined)
  }
  if (!added || added.exitCode !== 0) return `${host} is paired and trusted, but adding the server failed: ${added?.stderr.trim() ?? 'claude was not found'}`
  return `Connected: ${SERVER} is Deskward on ${host}. Restart Claude Code in this project, or reconnect ${SERVER} in /mcp, to use it.`
}

/** A tool result's content blocks, whether core hands over the blocks or the call's record. */
function blocksOf(result: unknown): Record<string, any>[] {
  if (Array.isArray(result)) return result
  const content = (result as { content?: unknown } | undefined)?.content
  return Array.isArray(content) ? content : []
}

/** Keeps one of the agent's screenshots for the pane: Deskward's small copy and what it marked. */
/** Whole numbers of a sane size, exactly `count` of them, or undefined. */
function ints<N extends number>(value: unknown, count: N): (number[] & { length: N }) | undefined {
  if (!Array.isArray(value) || value.length !== count) return undefined
  return value.every(n => Number.isInteger(n) && Math.abs(n) <= 1_000_000) ? (value as number[] & { length: N }) : undefined
}

/**
 * The marks a reply lists, kept only where every value is what Deskward sends: the target is
 * another computer, and these values go into markup the pane draws.
 */
function marksOf(drawn: unknown): Mark[] {
  if (!Array.isArray(drawn)) return []
  return drawn.slice(0, 32).flatMap((m): Mark[] => {
    const kind = m?.kind
    if (kind === 'found') {
      const box = ints(m.box, 4)
      return box ? [{ kind, box: box as [number, number, number, number] }] : []
    }
    if (kind === 'drag') {
      const from = ints(m.from, 2)
      const to = ints(m.to, 2)
      return from && to ? [{ kind, from: from as [number, number], to: to as [number, number] }] : []
    }
    if (kind === 'click' || kind === 'move' || kind === 'scroll') {
      const point = ints(m.at, 2)
      return point ? [{ kind, at: point as [number, number] }] : []
    }
    return []
  })
}

async function keep($: EngineInterface, id: string, at: number, ran: { text?: string; result?: unknown }) {
  const reply = json(ran.text)
  const region = ints(reply?.region, 4)
  if (!reply || !region || region[2]! <= 0 || region[3]! <= 0) return
  const block = Number.isInteger(reply.preview?.block) ? blocksOf(ran.result)[reply.preview.block] : undefined
  const raw = block?.data ?? block?.source?.data
  // Base64 alone, so nothing but the picture reaches the markup.
  const data = typeof raw === 'string' && /^[A-Za-z0-9+/]+={0,2}$/.test(raw) ? raw : undefined
  const kept = await read($, frames)
  const since = kept.at(-1)?.at ?? 0
  const steps = (await read($, actions))
    .filter(a => a.at > since && a.at < at && a.tool !== 'screenshot')
    .map(a => ({ tool: a.tool, outcome: a.outcome }))
  const frame: Frame = {
    id,
    at,
    jpeg: data,
    region: region as Frame['region'],
    marks: marksOf(reply.marks?.drawn),
    window: ints(reply.marks?.window, 4) as Frame['window'],
    steps,
  }
  await update($, frames, list => [...list, frame].slice(-KEPT_FRAMES))
  await update($, shown, () => null)
}

/** What a frame shows, in words: the pane's caption and the drawing's alt text. */
function describe(f: Frame): string {
  const said = f.marks.map((m: Mark) => {
    if (m.kind === 'click' && m.at) return `clicked ${m.at[0]}, ${m.at[1]}`
    if (m.kind === 'drag' && m.from && m.to) return `dragged ${m.from[0]}, ${m.from[1]} to ${m.to[0]}, ${m.to[1]}`
    if (m.kind === 'found') return 'found text'
    return m.kind === 'scroll' ? 'scrolled' : 'moved the pointer'
  })
  const unique = [...new Set(said)]
  return unique.length ? `Since the last look: ${unique.join(', ')}` : 'Nothing done since the last look'
}

/**
 * The screen as an SVG: Deskward's small copy, which has the marks drawn on it, over the same
 * marks in outline, so the marks still show where a surface leaves the picture out.
 */
function frameSvg(f: Frame): string {
  const [rx, ry, rw, rh] = f.region
  const height = Math.round((FRAME_WIDTH * rh) / Math.max(1, rw))
  const stroke = Math.max(2, Math.round(rw / 400))
  const r = Math.max(8, Math.round(rw / 80))
  const rect = (b: readonly [number, number, number, number], color: string) =>
    `<rect x="${b[0] - rx}" y="${b[1] - ry}" width="${b[2]}" height="${b[3]}" fill="none" stroke="${color}" stroke-width="${stroke}"/>`
  const ring = (p: readonly [number, number], color: string, size = r) =>
    `<circle cx="${p[0] - rx}" cy="${p[1] - ry}" r="${size}" fill="none" stroke="${color}" stroke-width="${stroke}"/>`
  const shapes = [
    f.window ? rect(f.window, '#378ADD') : '',
    ...f.marks.map(m => {
      if (m.kind === 'found' && m.box) return rect(m.box, '#EF9F27')
      if (m.kind === 'click' && m.at) return ring(m.at, '#D85A30')
      if (m.kind === 'drag' && m.from && m.to)
        return `<line x1="${m.from[0] - rx}" y1="${m.from[1] - ry}" x2="${m.to[0] - rx}" y2="${m.to[1] - ry}" stroke="#D85A30" stroke-width="${stroke}"/>${ring(m.to, '#D85A30')}`
      return m.at ? ring(m.at, '#888780', r / 2) : ''
    }),
  ].join('')
  const open = `<svg xmlns="http://www.w3.org/2000/svg" width="${FRAME_WIDTH}" height="${height}" viewBox="0 0 ${rw} ${rh}">`
  const base = `<rect width="${rw}" height="${rh}" fill="#E9EEF4"/>${shapes}`
  const picture = f.jpeg
    ? `<image href="data:image/jpeg;base64,${f.jpeg}" x="0" y="0" width="${rw}" height="${rh}" preserveAspectRatio="none"/>`
    : ''
  const whole = `${open}${base}${picture}</svg>`
  return whole.length <= SVG_LIMIT ? whole : `${open}${base}</svg>`
}

function clock(ms: number): string {
  const d = new Date(ms)
  const two = (n: number) => String(n).padStart(2, '0')
  return `${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}`
}

function span(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000))
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, '0')}s`
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, '0')}m`
}

/** The headline and its colour: what an agent may do on the target right now. */
function headline(s: Snapshot, at: number): { text: string; color: string; detail?: string } {
  const w = s.session
  if (s.error || !w) return { text: 'Unreachable', color: 'error', detail: s.error }
  if (s.stopFile) return { text: 'Stopped by a STOP file', color: 'error' }
  if (s.paused) return { text: 'Paused', color: 'warning', detail: s.pauseReason }
  if (!w.active) {
    if (w.state === 'Denied') return { text: 'Request rejected', color: 'error' }
    if (w.state === 'Stopped') return { text: 'Stopped by the person', color: 'error' }
    return { text: 'No session', color: 'subtle' }
  }
  if (!w.approved) return { text: 'Waiting for approval', color: 'warning', detail: 'The person approves on the VM' }
  const until = w.approvedUntil ? Date.parse(w.approvedUntil) : NaN
  const left = until - at
  const kind = w.viewOnly ? 'Approved to view' : 'Approved'
  if (Number.isNaN(until)) return { text: kind, color: 'success' }
  if (left > NO_LIMIT_MS) return { text: kind, color: 'success', detail: 'No time limit' }
  return { text: kind, color: left < 5 * 60 * 1000 ? 'warning' : 'success', detail: `${span(left)} left` }
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    let answered = false
    let since = 0

    const poll = async () => {
      const at = await $.clock.now()
      try {
        const result = await $.mcp.call(SERVER, 'status', {})
        const text = result.content.find(block => block.type === 'text') as { text?: string } | undefined
        const reply = json(text?.text)
        const read = result.isError ? snapshot(at, undefined, reply?.message ?? 'Deskward refused status') : snapshot(at, reply)
        await update($, status, () => read)
        if (!answered && !read.error) {
          answered = true
          void $.ui.open({ id: PANE, title: 'Deskward' })
        }
      } catch (error) {
        // A project with no deskward server, or one not connected yet: quiet, and asked less often.
        await update($, status, () => snapshot(at, undefined, String((error as Error)?.message ?? error)))
      }
    }

    await $.command.register({
      name: 'deskward',
      description: "Show the Deskward pane; /deskward connect <computer> adds a computer's Deskward to this project",
    })
    void poll()
    $.clock.every(1000, () => {
      since += 1000
      void (async () => {
        const at = await $.clock.now()
        // The countdown and "updated" line move every second only while a session is up.
        const current = await read($, status)
        if (current?.session?.active) await update($, now, () => at)
        if (since >= (answered ? POLL_MS : RETRY_MS)) {
          since = 0
          await poll()
          await update($, now, () => at)
        }
      })()
    })
    return next(e)
  })

  on('command.run', { command: 'deskward' }, async ($, e) => {
    const [verb, name = '', code] = e.args.trim().split(/\s+/)
    if (verb === 'connect') {
      const text = await connect($, name, code).catch(
        (error: unknown) => `Connecting stopped: ${String((error as Error)?.message ?? error)}. Nothing more was changed.`,
      )
      return { text }
    }
    await $.ui.open({ id: PANE, title: 'Deskward', focus: true })
    return { text: 'Deskward pane opened.' }
  })

  on('tool.call', async ($, e, next) => {
    // The pane's own status reads come through here too; only the agent's calls are listed.
    if (!e.tool.startsWith(PREFIX) || next.origin.plugin === $.plugin.name) return next(e)
    // The pane only watches: the call is made once, and a failure in its own bookkeeping, before
    // or after, never stops or changes it.
    let action: Action | undefined
    try {
      const at = await $.clock.now()
      action = { id: e.tool_use_id ?? `${e.tool}-${at}`, at, tool: e.tool.slice(PREFIX.length), outcome: 'running' }
      const listed = action
      await update($, actions, list => [...list, listed].slice(-KEPT_ACTIONS))
    } catch {
      action = undefined
    }
    // Asks Deskward for the small copy the pane replays; the agent's own image is unchanged.
    const shot = e.tool === `${PREFIX}screenshot`
    const ran = await next(shot && (e as Record<string, unknown>).preview === undefined ? ({ ...e, preview: true } as typeof e) : e)
    if (action && shot && ran.deny === undefined && !ran.isError) {
      try {
        await keep($, action.id, action.at, ran)
      } catch {
        // The replay misses this frame; the agent's call is unaffected.
      }
    }
    if (action) {
      const id = action.id
      try {
        const outcome =
          ran.deny !== undefined ? 'refused by Claude Code' : ran.isError ? String(json(ran.text)?.code ?? 'error') : 'ok'
        await update($, actions, list => list.map(one => (one.id === id ? { ...one, outcome } : one)))
      } catch {
        // The row keeps saying running; the agent's call is unaffected.
      }
    }
    return ran
  }).catch(($, e, next) =>
    // Reached only if the hook failed before calling next; next.called replays, never reruns.
    next(e),
  )

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const elements = $.ui.resolve(e)
    const { Box, Text, Button } = elements
    const Svg = 'Svg' in elements ? elements.Svg : undefined
    const s = await read($, status)
    const list = await read($, actions)
    const kept = await read($, frames)
    const picked = await read($, shown)
    const index = picked === null ? kept.length - 1 : Math.min(picked, kept.length - 1)
    const frame = index >= 0 ? kept[index] : undefined
    const at = Math.max(await read($, now), s?.at ?? 0)

    if (!s) {
      return (
        <Box flexDirection="column" padding={1}>
          <Text dimColor>Asking Deskward...</Text>
        </Box>
      )
    }

    const top = headline(s, at)
    const w = s.session
    const busy = typeof s.idleSeconds === 'number' && s.idleSeconds < 5
    const rows = Math.max(3, (e.props.scroll?.bodyRows ?? 24) - (frame ? 34 : 14))

    return (
      <Box flexDirection="column" padding={1} gap={1}>
        <Box flexDirection="column">
          <Text size="caption" color="subtle">
            {s.target ? `${s.target}${s.host ? `  ·  ${s.host}` : ''}` : 'Deskward'}
          </Text>
          <Text size="title" weight="semibold" color={top.color}>
            {top.text}
          </Text>
          {top.detail && <Text color={top.color}>{top.detail}</Text>}
        </Box>

        {w?.active && (
          <Box flexDirection="column">
            {w.label && <Text>Task: {w.label}</Text>}
            {w.requester && <Text color="subtle">Asked by {w.requester}</Text>}
            {w.extension && (
              <Text color="warning">
                Asked for {w.extension.minutes} more minutes: {w.extension.reason}
              </Text>
            )}
          </Box>
        )}

        {!s.error && (
          <Box flexDirection="column">
            <Text color={busy ? 'warning' : undefined}>
              {typeof s.idleSeconds !== 'number'
                ? 'Person: unknown'
                : busy
                  ? 'Person: using the computer now'
                  : `Person: away for ${span(s.idleSeconds * 1000)}`}
            </Text>
            <Text color={s.guardsReady ? undefined : 'error'}>
              {s.guardsReady ? 'Guards: ready' : `Guards: not ready${s.guardError ? `, ${s.guardError}` : ''}`}
            </Text>
            {s.desktopAvailable === false && <Text color="error">Desktop: locked or signed out</Text>}
          </Box>
        )}

        {frame && (
          <Box flexDirection="column" gap={1}>
            <Text size="caption" color="subtle">
              Screen at {clock(frame.at)}
              {kept.length > 1 ? `  ·  ${index + 1} of ${kept.length}` : ''}
            </Text>
            {Svg ? <Svg source={frameSvg(frame)} alt={describe(frame)} /> : null}
            <Text wrap="truncate-end">{describe(frame)}</Text>
            {frame.steps.length > 0 && (
              <Text mono dimColor wrap="truncate-end">
                {frame.steps.map(step => (step.outcome === 'ok' ? step.tool : `${step.tool} (${step.outcome})`)).join(', ')}
              </Text>
            )}
            {kept.length > 1 && (
              <Box flexDirection="row" gap={1}>
                <Button key="back" label="Back" onPress={() => update($, shown, () => Math.max(0, index - 1))} />
                <Button key="next" label="Next" onPress={() => update($, shown, () => (index + 1 >= kept.length - 1 ? null : index + 1))} />
                <Button key="latest" label="Latest" onPress={() => update($, shown, () => null)} />
              </Box>
            )}
          </Box>
        )}

        <Box flexDirection="column">
          <Text size="caption" color="subtle">
            Recent actions
          </Text>
          {list.length === 0 && <Text dimColor>None yet in this session.</Text>}
          {list.slice(-rows).reverse().map(a => (
            <Text
              mono
              wrap="truncate-end"
              dimColor={a.outcome === 'ok'}
              color={a.outcome === 'ok' || a.outcome === 'running' ? undefined : 'warning'}
            >
              {clock(a.at)}  {a.tool}  {a.outcome === 'ok' ? '' : a.outcome}
            </Text>
          ))}
        </Box>

        <Text size="caption" dimColor>
          Updated {span(at - s.at)} ago
        </Text>
      </Box>
    )
  })
}
