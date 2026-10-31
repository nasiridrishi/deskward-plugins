import { expect, test } from 'claude-code/testing'
import type { On } from 'claude-code'

import { blinding, constrainedAuthority, hex, mac, power, secret, sha256, spake, toBytes } from '../hooks/register'

const PRIME = BigInt(
  '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F2411' +
    '7C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497C' +
    'EA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',
)
const ORDER = (PRIME - 1n) / 2n
const utf8 = (text: string) => new TextEncoder().encode(text)
const LAB_SHA256 = '4dc9966d0e136260b8d9444f64d23da85c39f5bcfd75d7f03abfae64134399ee'
const CODE = '482913'

test('the exchange matches Deskward’s own, value for value', async () => {
  // The same fixed values as fixed_values_for_the_plugin in the Rust crate.
  expect(hex(await sha256(toBytes(await blinding('deskward spake2 M'))))).toBe(
    '3fb821837e5bcc98edc1db1b8075cfd609a9c7597d6d1240ab9ecae208c54316',
  )
  const n = await blinding('deskward spake2 N')
  const w = await secret('123456')
  const y = (power(2n, 7n) * power(n, w)) % PRIME
  const key = await (await spake('123456', 5n)).key(y)
  expect(hex(key)).toBe('161c853c32153c59cb382d4f999dfb5b9e4e31bfe0b48b05aa9b86be9fe8e472')
  expect(hex(await mac(key, [utf8('target'), utf8('ca')]))).toBe('99af784bc4a26c2970f68230f6fa2422dd518a6d82156c6e29b77258143284d5')
})

/** A Deskward on the far side of $.http.fetch, running its half of the exchange with `code`. */
function deskward(on: On, code: string, person: 'confirms' | 'cancels', certificate = (): string => CERTIFICATES.lab) {
  const ran: string[][] = []
  const stdins: string[] = []
  const state: { key?: Uint8Array; tokenHash?: string; finished?: boolean } = {}
  on('clock.now', () => ({ value: Date.parse('2026-10-31T10:00:00Z') }))
  on('clock.every', () => ({ value: { cancel: () => {} } }) as never)
  on('command.register', () => ({ value: { command: 'deskward' } }))
  on('session.start', (_, e) => ({ cwd: e.cwd }))
  on('session.cwd', () => ({ value: '/work' }))
  on('ui.open', () => ({ value: { isPlaced: true } }))
  on('ui.toast', () => ({ value: undefined }))
  on('mcp.call', () => ({ value: { content: [{ type: 'text', text: '{}' }], isError: false } }))
  on('fs.write', () => ({ value: undefined }))
  const reply = (body: unknown) => ({ value: { status: 200, ok: true, headers: {}, text: JSON.stringify(body) } })
  on('http.fetch', async (_, e) => {
    const asked = JSON.parse(e.init?.body ?? '{}')
    if (e.url === 'http://lab.local:47391/pair/start') {
      const [m, n, w] = [await blinding('deskward spake2 M'), await blinding('deskward spake2 N'), await secret(code)]
      const x = BigInt(`0x${asked.x}`)
      const yExp = 1234567n
      const y = (power(2n, yExp) * power(n, w)) % PRIME
      const shared = power((x * power(m, ORDER - w)) % PRIME, yExp)
      const parts = [utf8('deskward spake2 v1'), toBytes(x), toBytes(y), toBytes(shared), toBytes(w)]
      const framed = parts.flatMap(p => {
        const l = new Uint8Array(8)
        new DataView(l.buffer).setBigUint64(0, BigInt(p.length))
        return [l, p]
      })
      state.key = await sha256(...framed)
      const confirm = hex(await mac(state.key, [utf8('target'), await sha256(der(certificate()))]))
      const pem = `-----BEGIN CERTIFICATE-----\n${certificate().replace(/.{64}/g, '$&\n')}\n-----END CERTIFICATE-----\n`
      return reply({ id: 'e1', y: hex(toBytes(y)), certificate: pem, confirm })
    }
    if (e.url === 'http://lab.local:47391/pair/finish') {
      const expected = hex(await mac(state.key!, [utf8('client'), utf8(asked.token_hash)]))
      if (expected !== asked.confirm) return { value: { status: 403, ok: false, headers: {}, text: '{"message":"bad code"}' } }
      state.tokenHash = asked.token_hash
      return reply({ waiting: true })
    }
    if (e.url.startsWith('http://lab.local:47391/pair/result')) {
      if (person === 'cancels') return reply({ paired: false })
      return reply({ paired: true, confirm: hex(await mac(state.key!, [utf8('paired'), utf8(state.tokenHash!)])) })
    }
    return { value: { status: 404, ok: false, headers: {}, text: '{}' } }
  })
  on('process.run', (_, e) => {
    ran.push([...e.argv])
    if (e.init?.stdin !== undefined) stdins.push(e.init.stdin)
    const out = (stdout: string) => ({ value: { exitCode: 0, stdout, stderr: '', isStdoutTruncated: false, isStderrTruncated: false } })
    switch (e.argv[0]) {
      case 'uname':
        return out('Darwin\n')
      case '/bin/sh':
        return out(e.argv[2]?.startsWith('printf') ? '/Users/office' : '')
      case 'scutil':
        return out('Office Mac\n')
      case 'mktemp':
        return out('/tmp/deskward.x1\n')
      case '/usr/bin/openssl':
        // What openssl reads back from the re-encoded file: the same certificate.
        return out(e.argv.includes('-fingerprint') ? `SHA256 Fingerprint=${LAB_SHA256.toUpperCase().replace(/(..)(?!$)/g, '$1:')}\n` : '')
      default:
        return out('')
    }
  })
  return { ran, state, stdins }
}

function connect($: { command: { run: (input: never) => Promise<{ text?: string }> } }, args: string) {
  return $.command.run({ command: 'deskward', args } as never)
}

test('the code alone pairs: the certificate it vouched for is trusted and the server added with a token never sent', async ($, on) => {
  const { ran, state, stdins } = deskward(on, CODE, 'confirms')
  await $.session.start({ cwd: '/work', surface: 'desktop', isInteractive: true })
  const result = await connect($, `connect Lab ${CODE}`)
  expect(result.text).toContain('Connected')
  expect(ran).toContainEqual(['security', 'add-trusted-cert', '-r', 'trustRoot', '-p', 'ssl', '/tmp/deskward.x1/deskward-ca.cer'])
  const add = ran.find(argv => argv[0] === 'claude' && argv[2] === 'add-json')!
  expect(add.slice(0, 6)).toEqual(['claude', 'mcp', 'add-json', '-s', 'local', 'deskward'])
  const helper = '/Users/office/.deskward/headers/lab.local'
  expect(JSON.parse(add[6]!)).toEqual({ type: 'http', url: 'https://lab.local:47391/mcp', headersHelper: helper })
  const wrote = ran.find(argv => argv[0] === '/bin/sh' && argv.includes(helper))!
  expect(wrote[2]).toContain('umask 077')
  const token = stdins.join('').match(/Bearer ([0-9a-f]{64})/)![1]!
  expect(hex(await sha256(utf8(token)))).toBe(state.tokenHash)
  expect(ran.flat().some(arg => arg.includes(token)), 'the token is on no command line').toBe(false)
})

test('a wrong code, or a Confirm not pressed, trusts nothing and adds nothing', async ($, on) => {
  const { ran } = deskward(on, '111111', 'confirms')
  await $.session.start({ cwd: '/work', surface: 'desktop', isInteractive: true })
  const wrong = await connect($, `connect lab ${CODE}`)
  expect(wrong.text).toContain('The code did not match')
  expect(ran.some(argv => argv[0] === 'security' || argv[0] === 'claude')).toBe(false)
})

test('a computer that knows the code but sends an authority without constraints gets nothing trusted', async ($, on) => {
  const { ran } = deskward(on, CODE, 'confirms', () => CERTIFICATES.unconstrained)
  await $.session.start({ cwd: '/work', surface: 'desktop', isInteractive: true })
  const refused = await connect($, `connect lab ${CODE}`)
  expect(refused.text).toContain('not limited to .local')
  expect(ran.some(argv => argv[0] === 'security' || argv[0] === 'claude')).toBe(false)
})

test('the person cancelling on the panel trusts nothing', async ($, on) => {
  const { ran } = deskward(on, CODE, 'cancels')
  await $.session.start({ cwd: '/work', surface: 'desktop', isInteractive: true })
  const cancelled = await connect($, `connect lab ${CODE}`)
  expect(cancelled.text).toContain('was not paired')
  expect(ran.some(argv => argv[0] === 'security' || argv[0] === 'claude')).toBe(false)
})

test('what is not a host name reaches no command', async ($, on) => {
  const { ran } = deskward(on, CODE, 'confirms')
  await $.session.start({ cwd: '/work', surface: 'desktop', isInteractive: true })
  expect((await connect($, 'connect lab;open$(x)')).text).toContain('Usage')
  expect((await connect($, 'connect lab 12ab56')).text).toContain('not a six-digit code')
  expect(ran.filter(argv => argv[0] !== 'uname')).toEqual([])
})

/** Real certificates: the lab's authority, one made the same way, and three that fall short: one
 * that excludes no address, one with no name constraints, and one that also excludes a name. */
const CERTIFICATES = {
  lab: 'MIICEDCCAbegAwIBAgIUUcxcZ1r6fs8nuSKCI5i08sybMMowCgYIKoZIzj0EAwIwODEjMCEGA1UEAwwaRGVza3dhcmQgb24gREVTS1dBUkQtTEFCLTExETAPBgNVBAoMCERlc2t3YXJkMB4XDTI2MTAzMDEwMzExNVoXDTM2MTAyODEwMzExNVowODEjMCEGA1UEAwwaRGVza3dhcmQgb24gREVTS1dBUkQtTEFCLTExETAPBgNVBAoMCERlc2t3YXJkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0BvRiaSbl9c2ifS0OrzU+1K9JFCQoHKC9bjT1BzNgmeXhBTZX/kC57ZPRpi7pllt2Cwf2+jyhieycs873w+UoqOBnjCBmzAOBgNVHQ8BAf8EBAMCAQYwVgYDVR0eAQH/BEwwSqAWMAeCBWxvY2FsMAuCCWxvY2FsaG9zdKEwMAqHCAAAAAAAAAAAMCKHIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMB0GA1UdDgQWBBTv8YDKCm1J4H0ODang4FHdoNdPljASBgNVHRMBAf8ECDAGAQH/AgEAMAoGCCqGSM49BAMCA0cAMEQCIBZfwCV6O6W4/8Z+9yEI4Q/L1dsuVW7BBowQFncTdnmAAiBgmkW77+MDcDLKKGQULrRCqQtJAoZwQAzYmZa/zXjuJw==',
  alike: 'MIIBxzCCAW2gAwIBAgIUbs8rjpLJnP5i6sox2xv7adjIVNYwCgYIKoZIzj0EAwIwEzERMA8GA1UEAwwIdCBleGNsaXAwHhcNMjYxMDMxMTAyOTIzWhcNMjYxMTMwMTAyOTIzWjATMREwDwYDVQQDDAh0IGV4Y2xpcDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBFQKxfno/qZi7HrkO7i6m1naOaLFbcI1ODTvaEw4b6EN5KqCAkaNFP/xc/0scr9sSJpRpyu9gvEQfGM/wJbDuajgZ4wgZswHQYDVR0OBBYEFBeNaOVnsmsjKuj4be5SXOjjl8oSMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgIEMFYGA1UdHgEB/wRMMEqgFjAHggVsb2NhbDALgglsb2NhbGhvc3ShMDAKhwgAAAAAAAAAADAihyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAKBggqhkjOPQQDAgNIADBFAiEA9Ih0jX5DyuIZX796dOfXmHplRA14aT7PsafSbg0HiiUCIAOnEed5KQ98/M8PEk41xl/yUTjxGR6PaLyoxXQFUnFf',
  addresses: 'MIIBljCCATugAwIBAgIUYliKvNpABAMCnYNMhEuiGzU7diEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJdCBkbnNvbmx5MB4XDTI2MTAzMTA5MDA1N1oXDTI2MTEzMDA5MDA1N1owFDESMBAGA1UEAwwJdCBkbnNvbmx5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb7dtJPhlEV8DvRKFiDJnSpNDCTNEKal2rRVaoro+/rBb2Ot7p3qGUzzJm+hmIcTKPy/3DMfjfWurU8x1KXQkhaNrMGkwHQYDVR0OBBYEFB8umehk6ptCajZlEfHQ1hZCk7c2MBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgIEMCQGA1UdHgEB/wQaMBigFjAHggVsb2NhbDALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAKReKJc1czr7R6t9XD2MUDmKMw4g2P0xtX+tkciqGZiiAiEAiA14kNRoHwtCQjrYNBekBEZRcn3mql7fwRe1PDyAFDU=',
  unconstrained: 'MIIBeTCCASCgAwIBAgIUW3/MNy7M55NpEbqRUaqC0oE7fq0wCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQRGVza3dhcmQgb24gRVZJTDAeFw0yNjEwMzExMDI2NTFaFw0yNjExMzAxMDI2NTFaMBsxGTAXBgNVBAMMEERlc2t3YXJkIG9uIEVWSUwwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARA8qA2rgrDJoGTUg2uftrOfSEVFpbgaoM6sbmnhmzNP8FXnOcpqFJn0fRluQ+KQjvB1JybFwX7jS+NJdnjMANdo0IwQDAdBgNVHQ4EFgQU/nvQDYY4EqOpp3o7kDwyK8FZ6kIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwIDRwAwRAIgBT27c2wT0zVBFO+pWaFniXpgA5lQxbSNCkpKsu0ce7sCIDPwcs2UztThEzASuR+tZeTLJxM3w6zG2yOnO/UVhOCW',
  excluding: 'MIIBkDCCATagAwIBAgIUVz5EfJY2wn8OhECD2qBYHE6Pe1wwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQRGVza3dhcmQgb24gRVZJTDAeFw0yNjEwMzExMDI2NTFaFw0yNjExMzAxMDI2NTFaMBsxGTAXBgNVBAMMEERlc2t3YXJkIG9uIEVWSUwwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARE6hdFzM67khTjNqpNgiW17/DE9BF7EB9DvUBI59hUz1hfP7mDJhmCMYExj1DFjm4MnTIItTT6mYeMqKG7DLiGo1gwVjAdBgNVHQ4EFgQUR06sJmYoIMBJp7CXpEK1sXejjCIwDwYDVR0TAQH/BAUwAwEB/zAkBgNVHR4BAf8EGjAYoAkwB4IFbG9jYWyhCzAJggd4LmxvY2FsMAoGCCqGSM49BAMCA0gAMEUCIHDNl5d7T/SqVVJ5IT0j0JYdzhqhgiAUuR3YiB31k+MMAiEAu8cS7mV9H/nyO4hPFhGXN1dOEONsVnXCwGeWSdK51hY=',
}
const der = (b64: string) => Uint8Array.from(atob(b64), c => c.charCodeAt(0))

test('only an authority limited to .local and localhost and closed to every address passes, read from its DER', () => {
  expect(constrainedAuthority(der(CERTIFICATES.lab))).toBe(true)
  expect(constrainedAuthority(der(CERTIFICATES.alike))).toBe(true)
  expect(constrainedAuthority(der(CERTIFICATES.addresses))).toBe(false)
  expect(constrainedAuthority(der(CERTIFICATES.unconstrained))).toBe(false)
  expect(constrainedAuthority(der(CERTIFICATES.excluding))).toBe(false)
  expect(constrainedAuthority(Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x00))).toBe(false)
})
