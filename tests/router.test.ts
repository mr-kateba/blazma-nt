import { createHash, createHmac, pbkdf2Sync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { hashedPassword, scramClientProof } from '../src/backend/router/huaweiCrypto.js'
import { buildRequest, xmlList, xmlTag } from '../src/backend/router/huaweiClient.js'

describe('huawei SCRAM crypto', () => {
  it('reproduces the reference proof computation', () => {
    // Independent re-derivation using the same (Huawei-specific) HMAC ordering,
    // so this locks the algorithm against accidental change.
    const clientnonce = 'a'.repeat(64)
    const servernonce = 'b'.repeat(64)
    const password = 'hunter2'
    const salt = '00112233445566778899aabbccddeeff'
    const iterations = 100

    const authMsg = `${clientnonce},${servernonce},${servernonce}`
    const salted = pbkdf2Sync(password, Buffer.from(salt, 'hex'), iterations, 32, 'sha256')
    const clientKey = createHmac('sha256', 'Client Key').update(salted).digest()
    const storedKey = createHash('sha256').update(clientKey).digest()
    const signature = createHmac('sha256', authMsg).update(storedKey).digest()
    const expected = Buffer.alloc(32)
    for (let i = 0; i < 32; i++) expected[i] = clientKey[i] ^ signature[i]

    expect(scramClientProof(clientnonce, servernonce, password, salt, iterations)).toBe(
      expected.toString('hex')
    )
  })

  it('is deterministic and 64 hex chars', () => {
    const proof = scramClientProof('n1', 'n2', 'pw', 'abcd', 10)
    expect(proof).toMatch(/^[0-9a-f]{64}$/)
    expect(scramClientProof('n1', 'n2', 'pw', 'abcd', 10)).toBe(proof)
  })

  it('changes when the password changes', () => {
    const a = scramClientProof('n1', 'n2', 'pw1', 'abcd', 10)
    const b = scramClientProof('n1', 'n2', 'pw2', 'abcd', 10)
    expect(a).not.toBe(b)
  })

  it('computes the legacy hashed password', () => {
    const inner = createHash('sha256').update('secret').digest('base64')
    const expected = createHash('sha256').update(`admin${inner}TOKEN`).digest('base64')
    expect(hashedPassword('admin', 'secret', 'TOKEN')).toBe(expected)
  })
})

describe('huawei XML helpers', () => {
  it('reads a flat tag', () => {
    const xml = '<response><devicename>B628-350</devicename><spreadname_en>4G CPE Pro 3</spreadname_en></response>'
    expect(xmlTag(xml, 'devicename')).toBe('B628-350')
    expect(xmlTag(xml, 'spreadname_en')).toBe('4G CPE Pro 3')
    expect(xmlTag(xml, 'missing')).toBeNull()
  })

  it('decodes XML entities', () => {
    expect(xmlTag('<x>a &amp; b &lt;c&gt;</x>', 'x')).toBe('a & b <c>')
  })

  it('lists repeated elements', () => {
    const xml = '<Hosts><Host><MacAddress>AA</MacAddress></Host><Host><MacAddress>BB</MacAddress></Host></Hosts>'
    const hosts = xmlList(xml, 'Host')
    expect(hosts).toHaveLength(2)
    expect(xmlTag(hosts[0], 'MacAddress')).toBe('AA')
    expect(xmlTag(hosts[1], 'MacAddress')).toBe('BB')
  })

  it('builds a request body and escapes special characters', () => {
    const body = buildRequest({ Control: 1, name: 'a & <b>' })
    expect(body).toContain('<Control>1</Control>')
    expect(body).toContain('<name>a &amp; &lt;b&gt;</name>')
    expect(body.startsWith('<?xml')).toBe(true)
  })
})

import { HuaweiController } from '../src/backend/router/huaweiController.js'

/** A fake Huawei API returning canned XML per endpoint, to test parsing offline. */
function fakeApi(responses: Record<string, string>) {
  const calls: string[] = []
  return {
    calls,
    get: async (path: string) => {
      calls.push(path)
      if (responses[path] === undefined) throw new Error(`unexpected GET ${path}`)
      return responses[path]
    },
    post: async () => '<response>OK</response>',
    postRaw: async () => '<response>OK</response>'
  }
}

describe('huawei signal parsing', () => {
  it('reads network, bars, operator and radio metrics', async () => {
    const api = fakeApi({
      '/api/monitoring/status': '<response><CurrentNetworkType>19</CurrentNetworkType><SignalIcon>5</SignalIcon></response>',
      '/api/net/current-plmn': '<response><FullName>Example Telecom</FullName><Rat>7</Rat></response>',
      '/api/device/signal': '<response><rsrp>-95dBm</rsrp><rsrq>-10dB</rsrq><sinr>12dB</sinr></response>'
    })
    const sig = await new HuaweiController(api).signal()
    expect(sig.networkType).toBe('LTE')
    expect(sig.bars).toBe(5)
    expect(sig.operator).toBe('Example Telecom')
    expect(sig.rsrp).toBe('-95dBm')
    expect(sig.sinr).toBe('12dB')
  })

  it('still reports network and operator when the login-only endpoint fails', async () => {
    const api = fakeApi({
      '/api/monitoring/status': '<error><code>125002</code></error>',
      '/api/net/current-plmn': '<response><FullName>Example Telecom</FullName><Rat>7</Rat></response>',
      '/api/device/signal': '<error><code>100003</code></error>'
    })
    // get() throws on <error>; the controller catches per-endpoint.
    const throwingApi = {
      ...api,
      get: async (path: string) => {
        const xml = await api.get(path)
        if (/<error>/.test(xml)) throw new Error('api error')
        return xml
      }
    }
    const sig = await new HuaweiController(throwingApi).signal()
    expect(sig.networkType).toBe('LTE')
    expect(sig.operator).toBe('Example Telecom')
    expect(sig.rsrp).toBeNull()
    expect(sig.bars).toBeNull()
  })

  it('parses the WLAN MAC filter block list', async () => {
    const api = fakeApi({
      '/api/wlan/host-list': '<response><Hosts><Host><MacAddress>AA:BB:CC:DD:EE:01</MacAddress><HostName>phone</HostName><IpAddress>192.168.8.20</IpAddress></Host></Hosts></response>',
      '/api/wlan/multi-macfilter-settings':
        '<response><Ssids><Ssid><Index>0</Index><WifiMacFilterStatus>2</WifiMacFilterStatus><WifiMacFilterMac0>AA:BB:CC:DD:EE:01</WifiMacFilterMac0></Ssid></Ssids></response>'
    })
    const devices = await new HuaweiController(api).devices(new Set())
    expect(devices).toHaveLength(1)
    expect(devices[0].blocked).toBe(true)
    expect(devices[0].hostname).toBe('phone')
  })
})
