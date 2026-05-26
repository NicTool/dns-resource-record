import { test, describe } from 'node:test'
import assert from 'node:assert/strict'

import {
  encodeName,
  readWireName,
  decompressRdata,
  buildQuery,
  parseResponse,
  svcParamsToWire,
  wirePackDomain,
  wirePackDomainCompressed,
} from '../lib/wire.js'

// ── encodeName ────────────────────────────────────────────────────────────────

describe('encodeName', () => {
  test('single-label FQDN', () => {
    const buf = encodeName('example.')
    // \x07 e x a m p l e \x00
    assert.deepEqual([...buf], [7, 101, 120, 97, 109, 112, 108, 101, 0])
  })

  test('multi-label FQDN', () => {
    const buf = encodeName('www.example.com.')
    assert.deepEqual([...buf], [3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0])
  })

  test('root label produces empty-label + root terminator', () => {
    // '.' → strip dot → '' → split → [''] → length-0 label + trailing \x00
    const buf = encodeName('.')
    assert.deepEqual([...buf], [0, 0])
  })

  test('strips trailing dot before encoding', () => {
    const a = encodeName('example.')
    const b = encodeName('example')
    assert.deepEqual([...a], [...b])
  })
})

// ── readWireName ──────────────────────────────────────────────────────────────

describe('readWireName', () => {
  test('reads a non-compressed name', () => {
    // \x03 f o o \x03 b a r \x00
    const packet = Buffer.from([3, 102, 111, 111, 3, 98, 97, 114, 0])
    const { bytes, end } = readWireName(packet, 0)
    assert.deepEqual([...bytes], [3, 102, 111, 111, 3, 98, 97, 114, 0])
    assert.equal(end, 9)
  })

  test('follows a pointer-compressed name', () => {
    // packet: [0] \x03foo\x00  [5] \xc0\x00  (pointer back to offset 0)
    const packet = Buffer.from([3, 102, 111, 111, 0, 0xc0, 0x00])
    const { bytes, end } = readWireName(packet, 5)
    assert.deepEqual([...bytes], [3, 102, 111, 111, 0])
    assert.equal(end, 7) // end is just after the pointer (offset 5 + 2)
  })

  test('records end after first pointer', () => {
    // offset 0: \x03bar\x00  offset 5: \x03baz\x00  offset 10: \xc0\x00
    const packet = Buffer.from([3, 98, 97, 114, 0, 3, 98, 97, 122, 0, 0xc0, 0x00])
    const { end } = readWireName(packet, 10)
    assert.equal(end, 12) // two bytes consumed for the pointer
  })

  test('rejects a self-referential pointer', () => {
    // offset 0: \xc0\x00 — points to itself
    const packet = Buffer.from([0xc0, 0x00])
    assert.throws(() => readWireName(packet, 0), /pointer cycle detected/)
  })

  test('rejects a two-pointer cycle', () => {
    // offset 0: \xc0\x02   offset 2: \xc0\x00
    const packet = Buffer.from([0xc0, 0x02, 0xc0, 0x00])
    assert.throws(() => readWireName(packet, 0), /pointer cycle detected/)
  })

  test('rejects an over-long pointer chain', () => {
    // 200 unique-offset pointers, each pointing to the next two bytes ahead.
    // Final slot terminates with a zero byte so a non-protected reader would
    // still finish; the guard fires on chain length.
    const len = 200 * 2 + 1
    const packet = Buffer.alloc(len)
    for (let i = 0; i < 200; i++) {
      const next = (i + 1) * 2
      packet[i * 2] = 0xc0 | ((next >> 8) & 0x3f)
      packet[i * 2 + 1] = next & 0xff
    }
    // last pointer (offset 398) points to offset 400 which holds \x00
    packet[400] = 0
    assert.throws(() => readWireName(packet, 0), /pointer chain too long/)
  })

  test('rejects a name longer than 255 bytes', () => {
    // 5 chained 63-byte labels (5 * 64 = 320 bytes) + terminator
    const label = Buffer.concat([Buffer.from([63]), Buffer.alloc(63, 0x61)])
    const packet = Buffer.concat([label, label, label, label, label, Buffer.from([0])])
    assert.throws(() => readWireName(packet, 0), /name exceeds 255 bytes/)
  })

  test('rejects a truncated pointer (high byte at end of packet)', () => {
    // Single 0xc0 byte with no second byte
    const packet = Buffer.from([0xc0])
    assert.throws(() => readWireName(packet, 0), /truncated pointer/)
  })

  test('rejects a pointer whose target is past the packet end', () => {
    // 0xc0 0x80 → target offset 0x80 = 128, packet is only 2 bytes
    const packet = Buffer.from([0xc0, 0x80])
    assert.throws(() => readWireName(packet, 0), /pointer target out of bounds/)
  })

  test('rejects a truncated label (declared length exceeds packet)', () => {
    // \x05 with only 2 bytes following — declared label longer than packet
    const packet = Buffer.from([5, 0x61, 0x61])
    assert.throws(() => readWireName(packet, 0), /truncated label/)
  })

  test('rejects an unterminated name (no zero, no pointer)', () => {
    // \x02 a a — well-formed label, no terminator, no pointer
    const packet = Buffer.from([2, 0x61, 0x61])
    assert.throws(() => readWireName(packet, 0), /unterminated name/)
  })

  test('rejects a reserved label-type code (top two bits = 01 or 10)', () => {
    // \x40 is binary 01000000 — reserved per RFC 1035 §4.1.4
    const packet = Buffer.from([0x40, 0, 0])
    assert.throws(() => readWireName(packet, 0), /reserved label type/)
  })

  test('rejects offset out of bounds', () => {
    const packet = Buffer.from([0])
    assert.throws(() => readWireName(packet, 5), /offset out of bounds/)
  })

  test('rejects a name whose total wire length equals 256 octets (255 labels + terminator)', () => {
    // 4 × 63-byte labels: 4 × 64 = 256 octets before the terminator → 257 with it.
    // Even before adding the terminator, 256 > 255 trips the §3.1 cap.
    const label = Buffer.concat([Buffer.from([63]), Buffer.alloc(63, 0x61)])
    const packet = Buffer.concat([label, label, label, label, Buffer.from([0])])
    assert.throws(() => readWireName(packet, 0), /name exceeds 255 bytes/)
  })
})

// ── wirePackDomainCompressed ──────────────────────────────────────────────────

describe('wirePackDomainCompressed', () => {
  test('first name writes uncompressed and matches wirePackDomain', () => {
    const dict = new Map()
    const buf = wirePackDomainCompressed('www.example.com.', dict, 12)
    assert.deepEqual([...buf], [...wirePackDomain('www.example.com.')])
  })

  test('second name with shared suffix emits a pointer', () => {
    const dict = new Map()
    // First, place "www.example.com." at offset 12.
    const first = wirePackDomainCompressed('www.example.com.', dict, 12)
    // Second name shares the "example.com." suffix.
    const second = wirePackDomainCompressed('mail.example.com.', dict, 12 + first.length)
    // Second name should be: \x04 m a i l <pointer to "example.com." inside first>
    // "example.com." starts at offset 12 + 4 (skip "\x03www") = 16.
    assert.deepEqual([...second.slice(0, 5)], [4, 0x6d, 0x61, 0x69, 0x6c])
    assert.equal(second[5], 0xc0)
    assert.equal(second[6], 16)
    assert.equal(second.length, 7)
  })

  test('full-name reuse emits only a pointer', () => {
    const dict = new Map()
    const first = wirePackDomainCompressed('example.com.', dict, 12)
    const second = wirePackDomainCompressed('example.com.', dict, 12 + first.length)
    assert.equal(second.length, 2)
    assert.equal(second[0], 0xc0)
    assert.equal(second[1], 12)
  })

  test('root name (".") encodes as a single zero byte without compression', () => {
    const dict = new Map([['.', 0]])
    const buf = wirePackDomainCompressed('.', dict, 50)
    assert.deepEqual([...buf], [0])
  })

  test('round-trips through readWireName', () => {
    const dict = new Map()
    const a = wirePackDomainCompressed('foo.example.com.', dict, 0)
    const b = wirePackDomainCompressed('bar.example.com.', dict, a.length)
    const packet = Buffer.concat([Buffer.from(a), Buffer.from(b)])
    const read1 = readWireName(packet, 0)
    const read2 = readWireName(packet, a.length)
    // Both decoded names should round-trip to the original uncompressed wire form.
    assert.deepEqual([...read1.bytes], [...wirePackDomain('foo.example.com.')])
    assert.deepEqual([...read2.bytes], [...wirePackDomain('bar.example.com.')])
  })
})

// ── decompressRdata ───────────────────────────────────────────────────────────

describe('decompressRdata', () => {
  // Build a packet where \x03ns1\x07example\x03com\x00 lives at offset 12
  // and the rdata is a pointer \xc0\x0c back to it.

  function makePacket(rdataBytes) {
    // 12 bytes of header padding + rdata
    return Buffer.concat([Buffer.alloc(12), rdataBytes])
  }

  test('unknown type returns raw slice', () => {
    const rdata = Buffer.from([1, 2, 3, 4])
    const packet = makePacket(rdata)
    const result = decompressRdata(packet, 12, 4, 99)
    assert.deepEqual([...result], [1, 2, 3, 4])
  })

  test('type 2 (NS) decompresses single name', () => {
    // Inline name \x03ns1\x00 in rdata
    const nameBytes = Buffer.from([3, 110, 115, 49, 0])
    const packet = makePacket(nameBytes)
    const result = decompressRdata(packet, 12, nameBytes.length, 2)
    assert.deepEqual([...result], [...nameBytes])
  })

  test('type 5 (CNAME) decompresses single name', () => {
    const nameBytes = Buffer.from([4, 104, 111, 115, 116, 0])
    const packet = makePacket(nameBytes)
    const result = decompressRdata(packet, 12, nameBytes.length, 5)
    assert.deepEqual([...result], [...nameBytes])
  })

  test('type 15 (MX) decompresses pref + name', () => {
    // pref=10, name=\x04mail\x00
    const pref = Buffer.from([0, 10])
    const name = Buffer.from([4, 109, 97, 105, 108, 0])
    const rdata = Buffer.concat([pref, name])
    const packet = makePacket(rdata)
    const result = decompressRdata(packet, 12, rdata.length, 15)
    assert.deepEqual([...result], [...pref, ...name])
  })

  test('type 33 (SRV) decompresses 6-byte head + name', () => {
    // priority=1, weight=0, port=80, name=\x03www\x00
    const head = Buffer.from([0, 1, 0, 0, 0, 80])
    const name = Buffer.from([3, 119, 119, 119, 0])
    const rdata = Buffer.concat([head, name])
    const packet = makePacket(rdata)
    const result = decompressRdata(packet, 12, rdata.length, 33)
    assert.deepEqual([...result], [...head, ...name])
  })

  test('type 6 (SOA) decompresses mname + rname + tail', () => {
    const mname = Buffer.from([2, 110, 115, 0]) // \x02ns\x00
    const rname = Buffer.from([5, 97, 100, 109, 105, 110, 0]) // \x05admin\x00
    const tail = Buffer.alloc(20, 0)
    const rdata = Buffer.concat([mname, rname, tail])
    const packet = makePacket(rdata)
    const result = decompressRdata(packet, 12, rdata.length, 6)
    assert.deepEqual([...result], [...mname, ...rname, ...tail])
  })

  test('type 17 (RP) decompresses two names', () => {
    const mbox = Buffer.from([4, 109, 97, 105, 108, 0])
    const txt = Buffer.from([3, 116, 120, 116, 0])
    const rdata = Buffer.concat([mbox, txt])
    const packet = makePacket(rdata)
    const result = decompressRdata(packet, 12, rdata.length, 17)
    assert.deepEqual([...result], [...mbox, ...txt])
  })

  test('type 35 (NAPTR) decompresses header + 3 strings + name', () => {
    // order=0, pref=0, flags=\x01U, svc=\x03SIP, regexp=\x00, name=\x00
    const head = Buffer.from([0, 0, 0, 0])
    const flags = Buffer.from([1, 85]) // length 1, 'U'
    const svc = Buffer.from([3, 83, 73, 80]) // length 3, 'SIP'
    const regexp = Buffer.from([0]) // length 0
    const name = Buffer.from([0]) // root
    const rdata = Buffer.concat([head, flags, svc, regexp, name])
    const packet = makePacket(rdata)
    const result = decompressRdata(packet, 12, rdata.length, 35)
    assert.deepEqual([...result], [...head, ...flags, ...svc, ...regexp, ...name])
  })
})

// ── buildQuery ────────────────────────────────────────────────────────────────

describe('buildQuery', () => {
  test('returns a Buffer', () => {
    const q = buildQuery('example.com', 1)
    assert.ok(Buffer.isBuffer(q))
  })

  test('QDCOUNT is 1', () => {
    const q = buildQuery('example.com', 1)
    assert.equal(q.readUInt16BE(4), 1)
  })

  test('ARCOUNT is 1 (OPT record)', () => {
    const q = buildQuery('example.com', 1)
    assert.equal(q.readUInt16BE(10), 1)
  })

  test('question section contains encoded name', () => {
    const q = buildQuery('example.com', 1)
    const expectedName = encodeName('example.com')
    const questionStart = 12
    assert.deepEqual([...q.slice(questionStart, questionStart + expectedName.length)], [...expectedName])
  })

  test('OPT record type is 41', () => {
    const q = buildQuery('example.com', 1)
    const nameLen = encodeName('example.com').length
    // OPT record starts after header(12) + name + qtype(2) + qclass(2) + opt owner(1)
    const optTypeOffset = 12 + nameLen + 4 + 1
    assert.equal(q.readUInt16BE(optTypeOffset), 41)
  })

  test('RD flag is set', () => {
    const q = buildQuery('example.com', 1)
    assert.equal((q.readUInt16BE(2) >> 8) & 1, 1)
  })
})

// ── parseResponse ─────────────────────────────────────────────────────────────

describe('parseResponse', () => {
  test('non-zero rcode returns empty answers', () => {
    const packet = Buffer.alloc(12)
    packet.writeUInt16BE(0x8003, 2) // QR=1, RCODE=3 (NXDOMAIN)
    const result = parseResponse(packet)
    assert.equal(result.rcode, 3)
    assert.deepEqual(result.answers, [])
  })

  test('parses a minimal A record response', () => {
    // Build a minimal response: header + answer with owner=\x00 (root) A 1.2.3.4
    const header = Buffer.alloc(12)
    header.writeUInt16BE(0x8000, 2) // QR=1, RCODE=0
    header.writeUInt16BE(0, 4) // QDCOUNT=0
    header.writeUInt16BE(1, 6) // ANCOUNT=1

    // Owner: root (\x00), type=1(A), class=1(IN), ttl=300, rdlen=4, rdata=1.2.3.4
    const answer = Buffer.from([
      0x00, // owner = root
      0x00,
      0x01, // type = A
      0x00,
      0x01, // class = IN
      0x00,
      0x00,
      0x01,
      0x2c, // ttl = 300
      0x00,
      0x04, // rdlen = 4
      1,
      2,
      3,
      4, // rdata
    ])

    const packet = Buffer.concat([header, answer])
    const { rcode, answers } = parseResponse(packet)
    assert.equal(rcode, 0)
    assert.equal(answers.length, 1)
    assert.equal(answers[0].typeId, 1)
    assert.equal(answers[0].cls, 1)
    assert.deepEqual([...answers[0].rdataBytes], [1, 2, 3, 4])
  })
})

// ── svcParamsToWire ───────────────────────────────────────────────────────────

describe('svcParamsToWire', () => {
  test('empty string returns zero-length Uint8Array', () => {
    assert.equal(svcParamsToWire('').length, 0)
    assert.ok(svcParamsToWire('') instanceof Uint8Array)
  })

  test('null/undefined returns zero-length Uint8Array', () => {
    assert.equal(svcParamsToWire(null).length, 0)
    assert.equal(svcParamsToWire(undefined).length, 0)
  })

  test('unknown key is silently skipped', () => {
    const result = svcParamsToWire('unknownkey=foo')
    assert.equal(result.length, 0)
  })

  test('no-default-alpn (key 2) encodes 4-byte header with zero-length value', () => {
    const result = svcParamsToWire('no-default-alpn')
    assert.equal(result.length, 4)
    const dv = new DataView(result.buffer)
    assert.equal(dv.getUint16(0), 2) // key ID
    assert.equal(dv.getUint16(2), 0) // value length
  })

  test('port (key 3) encodes as uint16 big-endian', () => {
    const result = svcParamsToWire('port=8443')
    assert.equal(result.length, 6) // 4-byte header + 2-byte value
    const dv = new DataView(result.buffer)
    assert.equal(dv.getUint16(0), 3) // key ID
    assert.equal(dv.getUint16(2), 2) // value length
    assert.equal(dv.getUint16(4), 8443) // port value
  })

  test('alpn (key 1) encodes comma-separated list with length prefixes', () => {
    const result = svcParamsToWire('alpn="h2,h3"')
    // h2 = [2, 104, 50], h3 = [2, 104, 51]  → 6 bytes value
    // 4-byte header + 6 bytes = 10
    assert.equal(result.length, 10)
    const dv = new DataView(result.buffer)
    assert.equal(dv.getUint16(0), 1) // key ID = alpn
    assert.equal(dv.getUint16(2), 6) // value length
    // first entry: length=2, 'h', '2'
    assert.equal(result[4], 2)
    assert.equal(result[5], 104) // 'h'
    assert.equal(result[6], 50) // '2'
    // second entry: length=2, 'h', '3'
    assert.equal(result[7], 2)
    assert.equal(result[8], 104) // 'h'
    assert.equal(result[9], 51) // '3'
  })

  test('ipv4hint (key 4) encodes each address as 4 bytes', () => {
    const result = svcParamsToWire('ipv4hint=1.2.3.4')
    assert.equal(result.length, 8) // 4-byte header + 4 bytes
    const dv = new DataView(result.buffer)
    assert.equal(dv.getUint16(0), 4)
    assert.equal(dv.getUint16(2), 4)
    assert.deepEqual([...result.slice(4)], [1, 2, 3, 4])
  })

  test('ipv4hint with multiple addresses', () => {
    const result = svcParamsToWire('ipv4hint=1.2.3.4,5.6.7.8')
    assert.equal(result.length, 12) // 4-byte header + 8 bytes
    assert.deepEqual([...result.slice(4)], [1, 2, 3, 4, 5, 6, 7, 8])
  })

  test('ipv6hint (key 6) encodes ::1 as 16 bytes', () => {
    const result = svcParamsToWire('ipv6hint=::1')
    assert.equal(result.length, 20) // 4-byte header + 16 bytes
    const dv = new DataView(result.buffer)
    assert.equal(dv.getUint16(0), 6)
    assert.equal(dv.getUint16(2), 16)
    // ::1 = 15 zero bytes + 1
    assert.deepEqual([...result.slice(4, 19)], new Array(15).fill(0))
    assert.equal(result[19], 1)
  })

  test('params are sorted ascending by key ID (RFC 9460)', () => {
    // port (3) before alpn (1) in input — output must be alpn first
    const result = svcParamsToWire('port=443 alpn="h2"')
    const dv = new DataView(result.buffer)
    // First param key ID should be 1 (alpn), second should be 3 (port)
    const firstKeyId = dv.getUint16(0)
    assert.equal(firstKeyId, 1)
    // skip past first param: 4 header + value length
    const firstValLen = dv.getUint16(2)
    const secondKeyId = dv.getUint16(4 + firstValLen)
    assert.equal(secondKeyId, 3)
  })
})
