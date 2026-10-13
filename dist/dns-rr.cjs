'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

// RFC 1035 §5.1: in a presentation name, \. is a dot inside a label and
// \DDD is one octet. Splitting on '.' would break both.
function nameToLabels(name) {
  if (name === '.') return []
  const enc = new TextEncoder();
  const labels = [];
  let label = [];
  for (let i = 0; i < name.length; i++) {
    const c = name[i];
    if (c === '.') {
      if (!label.length) throw new Error(`DNS name has an empty label: ${name}`)
      labels.push(Uint8Array.from(label));
      label = [];
      continue
    }
    if (c === '\\') {
      if (++i === name.length) throw new Error(`DNS name ends in an incomplete escape: ${name}`)
      const decimal = name.slice(i, i + 3);
      if (/^[0-9]{3}$/.test(decimal) && Number(decimal) <= 255) {
        label.push(Number(decimal));
        i += 2;
        continue
      }
      if (/[0-9]/.test(name[i])) throw new Error(`DNS name has an invalid decimal escape: ${name}`)
    }
    const char = String.fromCodePoint(name.codePointAt(i));
    label.push(...enc.encode(char));
    i += char.length - 1;
  }
  if (label.length) labels.push(Uint8Array.from(label));
  for (const b of labels) {
    if (b.length > 63) throw new Error(`DNS label exceeds 63 bytes: ${name}`)
  }
  return labels
}

// A bare `*` is the RFC 4592 wildcard label; inside a longer label it is escaped.
function labelToPresentation(bytes) {
  if (bytes.length === 1 && bytes[0] === 0x2a) return '*'
  let out = '';
  for (const b of bytes) {
    const c = String.fromCharCode(b);
    if (c === '.' || c === '\\') out += `\\${c}`;
    else if (/[A-Za-z0-9\-_/]/.test(c)) out += c;
    else out += `\\${String(b).padStart(3, '0')}`;
  }
  return out
}

// RFC 1035 §5.1: \DDD is one octet and \X is X; other text is UTF-8.
function presentationBytes(text) {
  const enc = new TextEncoder();
  const bytes = [];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\\') {
      if (++i === text.length) throw new Error(`incomplete escape: ${text}`)
      if (/[0-9]/.test(text[i])) {
        const decimal = text.slice(i, i + 3);
        if (!/^[0-9]{3}$/.test(decimal) || Number(decimal) > 255)
          throw new Error(`invalid decimal escape: \\${decimal}`)
        bytes.push(Number(decimal));
        i += 2;
        continue
      }
    }
    const char = String.fromCodePoint(text.codePointAt(i));
    bytes.push(...enc.encode(char));
    i += char.length - 1;
  }
  return Uint8Array.from(bytes)
}

// RFC 4343: only ASCII A-Z fold, and an escaped octet (\X or \DDD) stands for
// the exact byte written.
function lowercaseName(name) {
  return name.replace(/\\(?:[0-9]{3}|.)|[A-Z]+/gs, (m) => (m[0] === '\\' ? m : m.toLowerCase()))
}

const octalRe = new RegExp(/\\(?:[1-7][0-7]{0,2}|[0-7]{2,3})/, 'g');

function parseFields(tinyline, rdataCount) {
  const parts = tinyline.slice(1).split(':');
  const owner = parts[0];
  const rdata = parts.slice(1, 1 + rdataCount);
  const [ttl, timestamp, location] = parts.slice(1 + rdataCount);
  return { owner, rdata, ttl, timestamp, location: location?.trim() ?? '' }
}

function parseGenericLine(tinyline) {
  // Generic form: :owner:typeId:rdata:ttl:timestamp:location
  const [owner, typeId, rdata, ttl, timestamp, location] = tinyline.slice(1).split(':');
  return { owner, typeId, rdata, ttl: parseInt(ttl, 10), timestamp, location: location?.trim() ?? '' }
}

function octalRdataToBytes(rdata) {
  return Uint8Array.from(octalToChar(rdata), (c) => c.charCodeAt(0))
}

function to(rrInstance) {
  // the class guard lives in getTinydnsPostamble(), which every line includes
  if (rrInstance.constructor.tinydnsType) {
    const fields = rrInstance.getFields('rdata');
    const rdata = fields
      .map((f) => {
        if (rrInstance.isFqdnField(f)) return rrInstance.getTinyFQDN(f)
        return rrInstance.get(f)
      })
      .join(':');
    return `${rrInstance.constructor.tinydnsType}${rrInstance.getTinyFQDN('owner')}:${rdata}:${rrInstance.getTinydnsPostamble()}\n`
  }
  return rrInstance.getTinydnsGeneric(bytesToTinydnsText(rrInstance.getWireRdata()))
}

function fromGeneric(rrInstance, { tinyline }) {
  const fields = rrInstance.getFields('rdata');
  const { owner, rdata, ttl, timestamp, location } = parseFields(tinyline, fields.length);

  const result = {
    owner: rrInstance.fullyQualify(owner),
    type: rrInstance.constructor.typeName,
    ttl: parseInt(ttl, 10),
    timestamp: timestamp,
    location: location,
  };

  for (let i = 0; i < fields.length; i++) {
    const val = rdata[i];
    result[fields[i]] = rrInstance.isFqdnField(fields[i]) ? rrInstance.fullyQualify(val) : val;
  }

  return new rrInstance.constructor(result)
}

function escapeOctal(re, str) {
  let escaped = '';
  str.split(/(.{1})/g).map((c) => {
    escaped += re.test(c) ? charToOctal(c) : c;
  });
  return escaped
}

function octalToChar(str) {
  // relace instances of \NNN with ASCII
  return str.replace(octalRe, (o) => String.fromCharCode(parseInt(o.slice(1), 8)))
}

function octalToHex(str) {
  // relace instances of \NNN with Hex
  return str.replace(octalRe, (o) => {
    // parseInt(n, 8) -> from octal to decimal
    //  .toString(16) -> decimal to hex
    return parseInt(o.slice(1), 8).toString(16).padStart(2, 0)
  })
}

function octalToUInt8(str) {
  return parseInt(str.slice(1, 4), 8) & 0xff
}

function octalToUInt16(str) {
  return (parseInt(str.slice(1, 4), 8) << 8) | parseInt(str.slice(5, 8), 8)
}

function octalToUInt32(str) {
  const b0 = parseInt(str.slice(1, 4), 8);
  const b1 = parseInt(str.slice(5, 8), 8);
  const b2 = parseInt(str.slice(9, 12), 8);
  const b3 = parseInt(str.slice(13, 16), 8);
  return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0
}

function packString(str) {
  return str
    .match(/(.{1,255})/g)
    .map((s) => `${UInt8toOctal(s.length)}${s}`)
    .join('')
}

function unpackString(str) {
  const asBuf = Uint8Array.from(octalToChar(str.toString()), (c) => c.charCodeAt(0));
  const dec = new TextDecoder();
  const res = [];
  let pos = 0;
  let len;
  while ((len = asBuf[pos])) {
    // encoded length byte
    pos++;
    res.push(dec.decode(asBuf.subarray(pos, pos + len)));
    pos = +(pos + len);
    if (pos >= asBuf.length) break
  }
  return res
}

function packDomainName(fqdn) {
  let packed = '';
  for (const label of nameToLabels(fqdn)) {
    packed += UInt8toOctal(label.length);
    for (const b of label) {
      const c = String.fromCharCode(b);
      packed += /[A-Za-z0-9-]/.test(c) ? c : UInt8toOctal(b);
    }
  }
  return packed + '\\000'
}

function unpackDomainName(escaped) {
  let pos = 0;
  let binaryLen = 0;
  const labels = [];

  // consume the next logical "byte" (char or octal escape)
  const getNextByte = () => {
    if (pos >= escaped.length) return null

    let value;
    if (escaped[pos] === '\\') {
      value = parseInt(escaped.slice(pos + 1, pos + 4), 8);
      pos += 4;
    } else {
      value = escaped.charCodeAt(pos++);
    }

    binaryLen++;
    return value
  };

  let lengthByte;
  while ((lengthByte = getNextByte()) && lengthByte !== 0) {
    const label = [];
    for (let i = 0; i < lengthByte; i++) {
      const byte = getNextByte();
      if (byte === null) break
      label.push(byte);
    }
    labels.push(labelToPresentation(label));
  }

  return [`${labels.join('.')}.`, pos, binaryLen]
}

function packHex(str) {
  let r = '';
  for (let i = 0; i < str.length; i = i + 2) {
    // nibble off 2 hex bytes, encode to octal
    r += UInt8toOctal(parseInt(str.slice(i, i + 2), 16));
  }
  return r
}

function charToOctal(c) {
  if (typeof c === 'number') return UInt8toOctal(c)

  return UInt8toOctal(c.charCodeAt(0))
}

function UInt8toOctal(n) {
  if (n > 255) {
    throw new Error(
      `UInt8toOctal: value ${n} exceeds 255 — tinydns encoders require Latin-1/byte input (code points <= 0xFF)`,
    )
  }

  return `\\${parseInt(n, 10).toString(8).padStart(3, 0)}`
}

function UInt16toOctal(n) {
  return UInt8toOctal((n >>> 8) & 0xff) + UInt8toOctal(n & 0xff)
}

function UInt32toOctal(n) {
  return (
    UInt8toOctal((n >>> 24) & 0xff) +
    UInt8toOctal((n >>> 16) & 0xff) +
    UInt8toOctal((n >>> 8) & 0xff) +
    UInt8toOctal(n & 0xff)
  )
}

function expandIPv6(val, delimiter = ':') {
  const colons = val.match(/:/g);
  if (colons?.length < 7) {
    val = val.replace(/::/, ':'.repeat(9 - colons.length));
  }
  return val
    .split(':')
    .map((s) => s.padStart(4, '0'))
    .join(delimiter)
    .toLowerCase()
}

function base64toOctal(str) {
  const binary = atob(str);
  let escaped = '';
  for (let i = 0; i < binary.length; i++) {
    const b = binary.charCodeAt(i);
    escaped += /[A-Za-z0-9\-.]/.test(binary[i]) ? binary[i] : UInt8toOctal(b);
  }
  return escaped
}

function octalToBase64(str) {
  return btoa(octalToChar(str))
}

// Printable ASCII stays readable; ':' and '\\' would end or escape a field.
function bytesToTinydnsText(bytes) {
  let out = '';
  for (const b of bytes) {
    const c = String.fromCharCode(b);
    out += b >= 0x20 && b < 0x7f && c !== ':' && c !== '\\' ? c : UInt8toOctal(b);
  }
  return out
}

// csv2(5) and csv2_txt(5): text inside '...' is literal, so ', |, ~, # and
// controls are written outside the quotes as \xNN escapes.
function quoteCharString(str) {
  let out = '';
  let quoted = false;
  for (const c of String(str)) {
    const code = c.codePointAt(0);
    const escaped = code < 0x20 || code === 0x7f || "'|~#".includes(c);
    if (escaped === quoted) {
      out += "'";
      quoted = !quoted;
    }
    out += escaped ? `\\x${code.toString(16).padStart(2, '0')}` : c;
  }
  if (quoted) out += "'";
  return out || "''"
}

function hexToBytes(hex) {
  return Uint8Array.from({ length: hex.length / 2 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16))
}

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function bytesToBase64(bytes) {
  return btoa([...bytes].map((b) => String.fromCharCode(b)).join(''))
}

function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
}

// DNS type name → numeric type ID mapping (subset covering known RR types)
const DNS_TYPE_IDS = {
  A: 1,
  NS: 2,
  MD: 3,
  MF: 4,
  CNAME: 5,
  SOA: 6,
  MB: 7,
  MG: 8,
  MR: 9,
  NULL: 10,
  WKS: 11,
  PTR: 12,
  HINFO: 13,
  MINFO: 14,
  MX: 15,
  TXT: 16,
  RP: 17,
  AFSDB: 18,
  X25: 19,
  ISDN: 20,
  RT: 21,
  NSAP: 22,
  NSAP_PTR: 23, // input-only alias; IANA registers the hyphenated form
  'NSAP-PTR': 23,
  SIG: 24,
  KEY: 25,
  PX: 26,
  GPOS: 27,
  AAAA: 28,
  LOC: 29,
  NXT: 30,
  EID: 31,
  NIMLOC: 32,
  SRV: 33,
  ATMA: 34,
  NAPTR: 35,
  KX: 36,
  CERT: 37,
  A6: 38,
  DNAME: 39,
  SINK: 40,
  OPT: 41,
  APL: 42,
  DS: 43,
  SSHFP: 44,
  IPSECKEY: 45,
  RRSIG: 46,
  NSEC: 47,
  DNSKEY: 48,
  DHCID: 49,
  NSEC3: 50,
  NSEC3PARAM: 51,
  TLSA: 52,
  SMIMEA: 53,
  HIP: 55,
  NINFO: 56,
  RKEY: 57,
  TALINK: 58,
  CDS: 59,
  CDNSKEY: 60,
  OPENPGPKEY: 61,
  CSYNC: 62,
  ZONEMD: 63,
  SVCB: 64,
  HTTPS: 65,
  SPF: 99,
  UINFO: 100,
  UID: 101,
  GID: 102,
  UNSPEC: 103,
  NID: 104,
  L32: 105,
  L64: 106,
  LP: 107,
  EUI48: 108,
  EUI64: 109,
  TKEY: 249,
  TSIG: 250,
  IXFR: 251,
  AXFR: 252,
  MAILB: 253,
  MAILA: 254,
  ANY: 255,
  URI: 256,
  CAA: 257,
  AVC: 258,
  DOA: 259,
  AMTRELAY: 260,
  TA: 32768,
  DLV: 32769,
};

const DNS_TYPE_NAMES = Object.fromEntries(Object.entries(DNS_TYPE_IDS).map(([k, v]) => [v, k]));

// 'MX' | 'TYPE123' (RFC 3597 §5) | '123' | 123  ->  numeric type id
function typeNameToId(type) {
  let id;
  if (typeof type === 'number') {
    id = type;
  } else if (typeof type === 'string') {
    const t = type.toUpperCase();
    const typeNN = t.match(/^TYPE(\d+)$/);
    if (typeNN) id = parseInt(typeNN[1], 10);
    else if (/^\d+$/.test(t)) id = parseInt(t, 10);
    else id = DNS_TYPE_IDS[t];
  }
  if (!Number.isInteger(id) || id < 0 || id > 65535) throw new Error(`invalid DNS type: ${String(type)}`)
  return id
}

// 15 -> 'MX', 731 -> 'TYPE731' (RFC 3597 §5)
function typeIdToName(id) {
  if (!Number.isInteger(id) || id < 0 || id > 65535) throw new Error(`invalid DNS type id: ${String(id)}`)
  return DNS_TYPE_NAMES[id] ?? `TYPE${id}`
}

// RFC 4034 §4.1.2 type bit maps, shared by NSEC and NSEC3.
function typesToBitmap(typeNames) {
  const windows = new Map();
  for (const name of typeNames.trim().split(/\s+/).filter(Boolean)) {
    const id = typeNameToId(name);
    const w = Math.floor(id / 256);
    if (!windows.has(w)) windows.set(w, []);
    windows.get(w).push(id % 256);
  }

  const blocks = [];
  for (const [wNum, bits] of [...windows.entries()].sort((a, b) => a[0] - b[0])) {
    const bitmapLen = Math.floor(Math.max(...bits) / 8) + 1;
    const bitmap = new Uint8Array(bitmapLen);
    for (const b of bits) bitmap[Math.floor(b / 8)] |= 0x80 >> (b % 8);
    blocks.push(Uint8Array.from([wNum, bitmapLen, ...bitmap]));
  }

  const result = new Uint8Array(blocks.reduce((s, b) => s + b.length, 0));
  let pos = 0;
  for (const b of blocks) {
    result.set(b, pos);
    pos += b.length;
  }
  return result
}

// RFC 4034 §4.1.2: blocks of 1-32 octets, windows ascending, no trailing zero octet.
function bitmapToTypes(bitmap) {
  const types = [];
  let pos = 0;
  let lastWindow = -1;
  while (pos < bitmap.length) {
    if (pos + 2 > bitmap.length) throw new Error('type bit map ends inside a block header')
    const windowNum = bitmap[pos];
    const bitmapLen = bitmap[pos + 1];
    if (windowNum <= lastWindow) throw new Error(`type bit map window ${windowNum} is out of order`)
    if (bitmapLen < 1 || bitmapLen > 32) throw new Error(`type bit map block length ${bitmapLen} is not 1-32`)
    if (pos + 2 + bitmapLen > bitmap.length) throw new Error('type bit map block is truncated')
    if (bitmap[pos + 1 + bitmapLen] === 0) throw new Error('type bit map block ends in a zero octet')
    pos += 2;
    for (let i = 0; i < bitmapLen; i++) {
      for (let bit = 0; bit < 8; bit++) {
        if (bitmap[pos + i] & (0x80 >> bit)) types.push(typeIdToName(windowNum * 256 + i * 8 + bit));
      }
    }
    pos += bitmapLen;
    lastWindow = windowNum;
  }
  return types.join(' ')
}

// RFC 4648 §7 base32hex, unpadded, as NSEC3 presents hashed owner names.
const BASE32HEX = '0123456789abcdefghijklmnopqrstuv';

function base32hexToBytes(str) {
  const bytes = [];
  let value = 0;
  let bits = 0;
  for (const c of str.toLowerCase()) {
    const v = BASE32HEX.indexOf(c);
    if (v === -1) throw new Error(`invalid base32hex: ${str}`)
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 0xff);
      value &= (1 << bits) - 1;
    }
  }
  return Uint8Array.from(bytes)
}

function bytesToBase32hex(bytes) {
  let out = '';
  let value = 0;
  let bits = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32HEX[(value >> bits) & 31];
      value &= (1 << bits) - 1;
    }
  }
  if (bits > 0) out += BASE32HEX[(value << (5 - bits)) & 31];
  return out
}

// ── Uncompressed domain name decoding ────────────────────────────────────────

/**
 * Decode a length-prefixed (uncompressed) DNS name from a Uint8Array.
 * Returns { fqdn: string, end: number } where end is the offset after the name.
 */
// Rdata names are uncompressed (RFC 3597 §4), so a length byte above 63 is malformed here.
function wireUnpackDomain(bytes, offset = 0) {
  const labels = [];
  let pos = offset;
  for (;;) {
    if (pos >= bytes.length) throw new Error('wire name runs past the end of the data')
    const len = bytes[pos];
    if (len === 0) break
    if (len > 63) throw new Error(`wire label length ${len} exceeds 63`)
    if (pos + 1 + len > bytes.length) throw new Error('wire label runs past the end of the data')
    labels.push(labelToPresentation(bytes.subarray(pos + 1, pos + 1 + len)));
    pos += 1 + len;
  }
  return { fqdn: labels.length ? labels.join('.') + '.' : '.', end: pos + 1 }
}

/**
 * Pack a fully qualified domain name into wire format (Uint8Array).
 * Domain labels are prefixed with their length; the name ends with a zero byte.
 */
function wirePackDomain(fqdn) {
  if (fqdn === '.') return new Uint8Array([0])
  const labels = nameToLabels(fqdn);

  const buf = new Uint8Array(labels.reduce((n, b) => n + b.length + 1, 1));
  let offset = 0;
  for (const b of labels) {
    buf[offset++] = b.length;
    buf.set(b, offset);
    offset += b.length;
  }
  buf[offset] = 0;
  return buf
}

/**
 * Get wire format rdata for an RR instance.
 * Derived classes should override this with direct RFC 1035 wire encoding.
 * Fallback uses toTinydns() as an intermediate (less efficient but works for all types).
 */
function getWireRdata(rrInstance) {
  const line = rrInstance.toTinydns();
  if (!line.startsWith(':')) {
    throw new Error(
      `${rrInstance.get('type')}: getWireRdata() not implemented. Override in rr/${rrInstance.get('type').toLowerCase()}.js`,
    )
  }
  // line: :fqdn:typeId:rdata:ttl:ts:loc\n
  // Extract octal-encoded rdata and decode
  const rdata = line.split(':')[3];
  return rrInstance.octalToUint8Array(rdata ?? '')
}

/**
 * Serialize an RR instance to DNS wire format (RFC 1035).
 * Combines owner name, type, class, TTL, and rdata.
 */
function toWire(rrInstance) {
  const rdata = rrInstance.getWireRdata();
  const owner = wirePackDomain(rrInstance.get('owner'));
  const result = new Uint8Array(owner.length + 10 + rdata.length);
  result.set(owner, 0);
  const meta = new DataView(result.buffer, owner.length, 10);
  meta.setUint16(0, rrInstance.getTypeId());
  meta.setUint16(2, rrInstance.getClassId());
  meta.setUint32(4, rrInstance.get('ttl'));
  meta.setUint16(8, rdata.length);
  result.set(rdata, owner.length + 10);
  return result
}

/**
 * RFC 3597 §§3+5: a record decoded from generic (opaque) rdata must re-encode
 * to exactly the same bytes — anything else means the rdata was misparsed or
 * would be silently altered (this library stores embedded names lowercase and
 * cannot preserve their case, so such rdata is rejected, not rewritten).
 */
function assertWireRoundTrip(rrInstance, rdata) {
  const reencoded = rrInstance.getWireRdata();
  if (reencoded.length === rdata.length && [...reencoded].every((b, i) => b === rdata[i])) return
  const lower = (b) => (b >= 0x41 && b <= 0x5a ? b + 0x20 : b);
  const caseOnly =
    reencoded.length === rdata.length && [...reencoded].every((b, i) => lower(b) === lower(rdata[i]));
  if (caseOnly)
    throw new Error(
      `${rrInstance.get('type')}: cannot preserve rdata case (RFC 3597 §3); this library stores names lowercase`,
    )
  throw new Error(`${rrInstance.get('type')}: rdata does not round-trip through wire encoding`)
}

/**
 * Deserialize wire format bytes into an RR instance.
 * Static method wrapper for RR.fromWire().
 */
function fromWireBytes(RRConstructor, wireBytes, wireUnpackFn) {
  const instance = new RRConstructor(null);
  const bytes = wireBytes instanceof Uint8Array ? wireBytes : new Uint8Array(wireBytes);
  const { fqdn: owner, end } = wireUnpackFn(bytes, 0);
  if (end + 10 > bytes.length) throw new Error(`${RRConstructor.typeName}: truncated wire record`)
  const view = new DataView(bytes.buffer, bytes.byteOffset);
  const typeId = view.getUint16(end);
  if (RRConstructor.typeId !== undefined && typeId !== RRConstructor.typeId)
    throw new Error(
      `${RRConstructor.typeName}: wire type id ${typeId} does not match ${RRConstructor.typeId}`,
    )
  const classNum = view.getUint16(end + 2);
  const RRClasses = { IN: 1, CS: 2, CH: 3, HS: 4, NONE: 254, ANY: 255 };
  const cls = Object.keys(RRClasses).find((k) => RRClasses[k] === classNum) ?? `CLASS${classNum}`; // RFC 3597 §5
  const ttl = view.getUint32(end + 4);
  const rdlen = view.getUint16(end + 8);
  if (end + 10 + rdlen !== bytes.length)
    throw new Error(
      `${RRConstructor.typeName}: RDLENGTH ${rdlen} does not match remaining ${bytes.length - end - 10} bytes`,
    )
  const rdata = bytes.slice(end + 10, end + 10 + rdlen);
  return instance.fromWire({ owner, cls, ttl, rdata, typeId })
}

/**
 * Generic fromWire decoder driven by rdataFields type annotations.
 * Supports u8, u16, u32, fqdn, hex, base64, str, qstr, charstr, qcharstr, charstrs, svcparams, ipv4, ipv6.
 * See rr/TEMPLATE.js for descriptions and example type usage.
 * Last typed field consumes all remaining bytes.
 */
function fromWireGeneric(rrInstance, { owner, cls, ttl, rdata }) {
  const result = { owner, ttl, class: cls, type: rrInstance.constructor.typeName };
  const rdataFields = rrInstance.constructor.rdataFields ?? [];
  const dv = new DataView(rdata.buffer, rdata.byteOffset);
  let pos = 0;

  for (let i = 0; i < rdataFields.length; i++) {
    const entry = rdataFields[i];
    const fieldName = Array.isArray(entry) ? entry[0] : entry;
    const fieldType = Array.isArray(entry) ? entry[1] : null;

    switch (fieldType) {
      case 'u8':
        result[fieldName] = rdata[pos++];
        break
      case 'u16':
      case 'rrtype':
        result[fieldName] = dv.getUint16(pos);
        pos += 2;
        break
      case 'certtype': {
        const certTypeNum = dv.getUint16(pos);
        const reverse = rrInstance.constructor.CERT_TYPES_REVERSE;
        result[fieldName] = reverse?.[certTypeNum] ?? certTypeNum;
        pos += 2;
        break
      }
      case 'u32':
        result[fieldName] = dv.getUint32(pos);
        pos += 4;
        break
      case 'fqdn': {
        const { fqdn, end } = wireUnpackDomain(rdata, pos);
        result[fieldName] = fqdn;
        pos = end;
        break
      }
      case 'hex':
        result[fieldName] = bytesToHex(rdata.subarray(pos)).toUpperCase();
        pos = rdata.length;
        break
      case 'base64':
        result[fieldName] = bytesToBase64(rdata.subarray(pos));
        pos = rdata.length;
        break
      case 'str':
        result[fieldName] = new TextDecoder().decode(rdata.subarray(pos));
        pos = rdata.length;
        break
      case 'qstr':
        result[fieldName] = new TextDecoder().decode(rdata.subarray(pos));
        pos = rdata.length;
        break
      case 'charstr': {
        const strLen = rdata[pos++];
        result[fieldName] = new TextDecoder().decode(rdata.subarray(pos, pos + strLen));
        pos += strLen;
        break
      }
      case 'qcharstr': {
        const strLen = rdata[pos++];
        result[fieldName] = new TextDecoder().decode(rdata.subarray(pos, pos + strLen));
        pos += strLen;
        break
      }
      case 'charstrs': {
        // RFC 1035 §3.3.14: each <character-string> on the wire is len-prefixed.
        // Preserve multi-string boundaries by returning an array when >1.
        const parts = [];
        while (pos < rdata.length) {
          const strLen = rdata[pos++];
          if (pos + strLen > rdata.length) {
            throw new Error('fromWireGeneric: truncated character-string in rdata')
          }
          parts.push(new TextDecoder().decode(rdata.subarray(pos, pos + strLen)));
          pos += strLen;
        }
        result[fieldName] = parts.length > 1 ? parts : (parts[0] ?? '');
        break
      }
      case 'svcparams':
        result[fieldName] = svcParamsFromWire(rdata.subarray(pos));
        pos = rdata.length;
        break
      case 'ipv4':
        result[fieldName] = [...rdata.subarray(pos, pos + 4)].join('.');
        pos += 4;
        break
      case 'ipv6': {
        const parts = [];
        for (let j = 0; j < 16; j += 2) {
          parts.push(
            dv
              .getUint16(pos + j)
              .toString(16)
              .padStart(4, '0'),
          );
        }
        result[fieldName] = parts.join(':');
        pos += 16;
        break
      }
      default:
        result[fieldName] = rdata[pos++];
        break
    }
  }

  if (pos !== rdata.length) {
    const typeName = rrInstance.constructor.typeName;
    if (pos > rdata.length) throw new Error(`${typeName}: rdata is truncated`)
    throw new Error(`${typeName}: ${rdata.length - pos} rdata bytes after the last field`)
  }
  return new rrInstance.constructor(result)
}

// ── SVCB/HTTPS parameter encoding (RFC 9460) ─────────────────────────────────

const SVCPARAM_KEYS = {
  mandatory: 0,
  alpn: 1,
  'no-default-alpn': 2,
  port: 3,
  ipv4hint: 4,
  ech: 5,
  ipv6hint: 6,
};

/**
 * Encode SVCB/HTTPS params string (e.g. 'alpn="h2,h3" port="8443"') to wire bytes.
 */
function svcParamsToWire(paramsStr) {
  if (!paramsStr || !paramsStr.trim()) return new Uint8Array(0)

  const parts = new Map();
  for (const [key, value] of svcParamTokens(paramsStr)) {
    const keyId = svcParamKeyId(key.toLowerCase());
    if (parts.has(keyId)) throw new Error(`SVCB: duplicate SvcParamKey: ${key}`)
    const bytes = svcParamValue(keyId, key, value);
    // SvcParamValue length is 16 bits
    if (bytes.length > 65535) throw new Error(`SVCB: ${key} value is ${bytes.length} bytes, over 65535`)
    parts.set(keyId, bytes);
  }

  // RFC 9460 §2.2: keys in ascending order
  const params = [...parts.entries()].sort((a, b) => a[0] - b[0]);
  const result = new Uint8Array(params.reduce((n, [, v]) => n + 4 + v.length, 0));
  const dv = new DataView(result.buffer);
  let pos = 0;
  for (const [keyId, value] of params) {
    dv.setUint16(pos, keyId);
    dv.setUint16(pos + 2, value.length);
    result.set(value, pos + 4);
    pos += 4 + value.length;
  }
  return result
}

// Whitespace-separated key, key=value or key="value", in one pass so the cost
// stays linear in the input.
function svcParamTokens(str) {
  const isSpace = (c) => c === ' ' || c === '\t' || c === '\n' || c === '\r';
  const tokens = [];
  let i = 0;
  for (;;) {
    while (i < str.length && isSpace(str[i])) i++;
    if (i === str.length) return tokens
    const keyStart = i;
    while (i < str.length && str[i] !== '=' && !isSpace(str[i])) i++;
    const key = str.slice(keyStart, i);
    let value;
    if (str[i] === '=') {
      i++;
      if (str[i] === '"') {
        // an escaped quote (\") belongs to the value
        let close = i + 1;
        while (close < str.length && str[close] !== '"') close += str[close] === '\\' ? 2 : 1;
        if (close >= str.length) throw new Error(`SVCB: unterminated quoted value for ${key}`)
        value = str.slice(i + 1, close);
        i = close + 1;
        if (i < str.length && !isSpace(str[i])) throw new Error(`SVCB: text after the quoted value of ${key}`)
      } else {
        const valueStart = i;
        while (i < str.length && !isSpace(str[i])) i += str[i] === '\\' ? 2 : 1;
        value = str.slice(valueStart, Math.min(i, str.length));
      }
    }
    tokens.push([key, value]);
  }
}

const IPV4 = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

function ipv6Bytes(addr) {
  const halves = addr.split('::');
  const groups = halves.map((h) => (h ? h.split(':') : []));
  const count = groups.reduce((n, g) => n + g.length, 0);
  const valid =
    halves.length <= 2 &&
    groups.flat().every((g) => /^[0-9a-fA-F]{1,4}$/.test(g)) &&
    (halves.length === 2 ? count < 8 : count === 8);
  if (!valid) throw new Error(`SVCB: invalid IPv6 address: ${addr}`)
  const all = halves.length === 2 ? [...groups[0], ...Array(8 - count).fill('0'), ...groups[1]] : groups[0];
  return hexToBytes(all.map((g) => g.padStart(4, '0')).join(''))
}

// RFC 9460 §7: the presentation value of each registered key.
function svcParamValue(keyId, key, val) {
  const list = () => {
    if (!val) throw new Error(`SVCB: ${key} requires a value`)
    return val.split(',').map((e) => e.trim())
  };
  switch (keyId) {
    case 0: {
      const ids = list().map((k) => svcParamKeyId(k.toLowerCase()));
      if (ids.includes(0)) throw new Error('SVCB: mandatory may not list itself')
      if (new Set(ids).size !== ids.length) throw new Error('SVCB: mandatory lists a key twice')
      const bytes = new Uint8Array(ids.length * 2);
      ids.sort((a, b) => a - b).forEach((id, i) => new DataView(bytes.buffer).setUint16(i * 2, id));
      return bytes
    }
    case 1: {
      if (!val) throw new Error('SVCB: alpn requires a value')
      const entries = splitValueList(presentationBytes(val));
      if (entries.some((e) => e.length < 1 || e.length > 255))
        throw new Error(`SVCB: alpn ids must be 1-255 bytes: ${val}`)
      return Uint8Array.from(entries.flatMap((e) => [e.length, ...e]))
    }
    case 2:
      if (val !== undefined) throw new Error('SVCB: no-default-alpn takes no value')
      return new Uint8Array(0)
    case 3: {
      if (!/^\d+$/.test(val ?? '') || Number(val) > 65535)
        throw new Error(`SVCB: port must be 0-65535: ${val}`)
      return Uint8Array.from([Number(val) >> 8, Number(val) & 0xff])
    }
    case 4: {
      const addrs = list();
      const bad = addrs.find((a) => !IPV4.test(a));
      if (bad !== undefined) throw new Error(`SVCB: invalid IPv4 address: ${bad}`)
      return Uint8Array.from(addrs.flatMap((a) => a.split('.').map(Number)))
    }
    case 5:
      if (!val || !/^[A-Za-z0-9+/]+={0,2}$/.test(val) || val.length % 4)
        throw new Error(`SVCB: ech must be base64: ${val}`)
      return base64ToBytes(val)
    case 6:
      return Uint8Array.from(list().flatMap((a) => [...ipv6Bytes(a)]))
    default:
      return presentationBytes(val ?? '')
  }
}

// The key ids in a params string, in wire order. Throws on a malformed key.
function svcParamKeyIds(paramsStr) {
  const bytes = svcParamsToWire(paramsStr);
  const ids = [];
  for (let pos = 0; pos + 4 <= bytes.length;) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset + pos);
    ids.push(dv.getUint16(0));
    pos += 4 + dv.getUint16(2);
  }
  return ids
}

// RFC 9460 §2.1: a key is a registered name or keyNNNN.
function svcParamKeyId(key) {
  const generic = key.match(/^key(\d{1,5})$/);
  const id = generic ? Number(generic[1]) : SVCPARAM_KEYS[key];
  if (id === undefined || id > 65535) throw new Error(`SVCB: unknown SvcParamKey: ${key}`)
  if (id === 65535) throw new Error('SVCB: key65535 is reserved (RFC 9460 §14.3.2)')
  return id
}

// Unquoted presentation: printable ASCII except delimiters, everything else \DDD.
// RFC 9460 Appendix A.1: a value list is RFC 1035 decoded first, then split on
// commas, where `\,` and `\\` stand for a literal comma and backslash.
function splitValueList(bytes) {
  const items = [[]];
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0x5c && i + 1 < bytes.length) items.at(-1).push(bytes[++i]);
    else if (bytes[i] === 0x2c) items.push([]);
    else items.at(-1).push(bytes[i]);
  }
  return items.map((item) => Uint8Array.from(item))
}

// The inverse: escape commas and backslashes per item, then RFC 1035 escape for
// a quoted string.
function alpnToPresentation(ids) {
  const listed = ids.map((id) => [...id].flatMap((b) => (b === 0x2c || b === 0x5c ? [0x5c, b] : [b])));
  return listed
    .map((id) =>
      id
        .map((b) => {
          if (b === 0x22 || b === 0x5c) return `\\${String.fromCharCode(b)}`
          return b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : `\\${String(b).padStart(3, '0')}`
        })
        .join(''),
    )
    .join(',')
}

function svcValueToPresentation(bytes) {
  return [...bytes]
    .map((b) =>
      b > 0x20 && b < 0x7f && !'"\\;()'.includes(String.fromCharCode(b))
        ? String.fromCharCode(b)
        : `\\${String(b).padStart(3, '0')}`,
    )
    .join('')
}

const SVCPARAM_KEY_NAMES = {
  0: 'mandatory',
  1: 'alpn',
  2: 'no-default-alpn',
  3: 'port',
  4: 'ipv4hint',
  5: 'ech',
  6: 'ipv6hint',
};

/**
 * Decode SVCB/HTTPS wire params bytes back to a human-readable params string.
 */
function svcParamsFromWire(bytes) {
  if (!bytes || bytes.length === 0) return ''
  const parts = [];
  let pos = 0;
  let lastKey = -1;
  while (pos < bytes.length) {
    if (pos + 4 > bytes.length) throw new Error('SVCB: params end inside a key header')
    const dv = new DataView(bytes.buffer, bytes.byteOffset + pos);
    const keyId = dv.getUint16(0);
    const valLen = dv.getUint16(2);
    if (keyId <= lastKey) throw new Error(`SVCB: key ${keyId} is out of order or repeated`)
    if (pos + 4 + valLen > bytes.length) throw new Error(`SVCB: key ${keyId} value is truncated`)
    const val = bytes.subarray(pos + 4, pos + 4 + valLen);
    pos += 4 + valLen;
    lastKey = keyId;
    const badLength = {
      0: valLen === 0 || valLen % 2,
      2: valLen !== 0,
      3: valLen !== 2,
      4: valLen === 0 || valLen % 4,
      6: valLen === 0 || valLen % 16,
    }[keyId];
    if (badLength) throw new Error(`SVCB: key ${keyId} has an invalid length ${valLen}`)

    const keyName = SVCPARAM_KEY_NAMES[keyId] ?? `key${keyId}`;
    if (keyId === 0) {
      const names = [];
      let lastId = -1;
      for (let i = 0; i + 1 < val.length; i += 2) {
        const id = new DataView(val.buffer, val.byteOffset + i).getUint16(0);
        // RFC 9460 §8: keys sorted in increasing numeric order, no duplicates
        if (id <= lastId) throw new Error(`SVCB: mandatory key ${id} is out of order or repeated`)
        lastId = id;
        names.push(SVCPARAM_KEY_NAMES[id] ?? `key${id}`);
      }
      parts.push(`mandatory=${names.join(',')}`);
    } else if (keyId === 1) {
      // alpn: comma-separated length-prefixed entries
      const entries = [];
      let p = 0;
      while (p < val.length) {
        const len = val[p++];
        if (len === 0 || p + len > val.length) throw new Error('SVCB: malformed alpn value')
        entries.push(val.subarray(p, p + len));
        p += len;
      }
      parts.push(`alpn="${alpnToPresentation(entries)}"`);
    } else if (keyId === 2) {
      parts.push('no-default-alpn');
    } else if (keyId === 3) {
      parts.push(`port=${new DataView(val.buffer, val.byteOffset).getUint16(0)}`);
    } else if (keyId === 4) {
      const addrs = [];
      for (let i = 0; i < val.length; i += 4) addrs.push([...val.subarray(i, i + 4)].join('.'));
      parts.push(`ipv4hint=${addrs.join(',')}`);
    } else if (keyId === 5) {
      parts.push(`ech=${btoa([...val].map((b) => String.fromCharCode(b)).join(''))}`);
    } else if (keyId === 6) {
      const addrs = [];
      for (let i = 0; i < val.length; i += 16) {
        const dv16 = new DataView(val.buffer, val.byteOffset + i);
        const groups = [];
        for (let j = 0; j < 16; j += 2) groups.push(dv16.getUint16(j).toString(16).padStart(4, '0'));
        addrs.push(groups.join(':'));
      }
      parts.push(`ipv6hint=${addrs.join(',')}`);
    } else {
      parts.push(`${keyName}=${svcValueToPresentation(val)}`);
    }
  }
  return parts.join(' ')
}

/**
 * NicTool 2.x storage columns <-> RFC/IETF resource-record field names.
 *
 * NicTool stores every record type in the same handful of columns — `address`
 * holds the rdata, with `weight`, `priority`, `other` and `description` reused
 * per type — while this library names fields as the RFCs do. These maps
 * translate between the two, so a record read straight from the NicTool schema
 * can be handed to the matching RR class and exported with toBind() or
 * toTinydns().
 *
 * Types whose rdata packs several fields into `address` (NAPTR, NSEC3, SOA...)
 * are unpacked explicitly in unApplyMap.
 */

/**
 * Values are arrays for the packed types, so freeze those too. Freezing makes
 * the caches safe to share: mutating a map is a TypeError under ESM's strict mode
 */
function freezeMap(map) {
  for (const value of Object.values(map)) {
    if (Array.isArray(value)) Object.freeze(value);
  }
  return Object.freeze(map)
}

// A zone export maps once per record — millions of them for a large install —
// so build each type's map, and its entries, once.
const mapCache = new Map();
const entriesCache = new WeakMap();

function mapEntries(map) {
  let entries = entriesCache.get(map);
  if (entries === undefined) {
    entries = Object.entries(map);
    entriesCache.set(map, entries);
  }
  return entries
}

function getMap(rrType) {
  let map = mapCache.get(rrType);
  if (map === undefined) {
    map = freezeMap(mapFor(rrType));
    mapCache.set(rrType, map);
  }
  return map
}

function mapFor(rrType) {
  switch (rrType) {
    case 'CAA':
      return {
        weight: 'flags',
        other: 'tag',
        address: 'value',
      }
    case 'CERT':
      return {
        other: 'cert type',
        priority: 'key tag',
        weight: 'algorithm',
        address: 'certificate',
      }
    case 'CNAME':
      return { address: 'cname' }
    case 'DNAME':
      return { address: 'target' }
    case 'DNSKEY':
      return {
        address: 'publickey',
        weight: 'flags',
        priority: 'protocol',
        other: 'algorithm',
      }
    case 'DS':
      return {
        address: 'digest',
        weight: 'digest type',
        priority: 'algorithm',
        other: 'key tag',
      }
    case 'HINFO':
      return { address: 'os', other: 'cpu' }
    case 'HTTPS':
      return {
        address: 'target name',
        other: 'params',
      }
    case 'IPSECKEY':
      return {
        address: 'gateway',
        description: 'publickey',
        weight: 'precedence',
        priority: 'gateway type',
        other: 'algorithm',
      }
    case 'KEY':
      return {
        address: 'publickey',
        weight: 'protocol',
        priority: 'algorithm',
        other: 'flags',
      }
    case 'MX':
      return { weight: 'preference', address: 'exchange' }
    case 'NAPTR':
      return {
        weight: 'order',
        priority: 'preference',
        address: ['flags', 'service', 'regexp'],
        description: 'replacement',
      }
    case 'NS':
      return { address: 'dname' }
    case 'NSEC':
      return {
        address: 'next domain',
        description: 'type bit maps',
      }
    case 'NSEC3':
      return {
        address: ['hash algorithm', 'flags', 'iterations', 'salt', 'type bit maps', 'next hashed owner name'],
      }
    case 'NSEC3PARAM':
      return {
        address: ['hash algorithm', 'flags', 'iterations', 'salt'],
      }
    case 'NXT':
      return {
        address: 'next domain',
        description: 'type bit map',
      }
    case 'OPENPGPKEY':
      return { address: 'public key' }
    case 'PTR':
      return { address: 'dname' }
    case 'SMIMEA':
      return {
        address: 'certificate association data',
        weight: 'matching type',
        priority: 'selector',
        other: 'certificate usage',
      }
    case 'SOA':
      return {
        address: ['mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum'],
      }
    case 'SPF':
      return { address: 'data' }
    case 'SSHFP':
      return {
        address: 'fingerprint',
        weight: 'algorithm',
        priority: 'fptype',
      }
    case 'SRV':
      return { address: 'target', other: 'port' }
    case 'SVCB':
      return {
        address: 'target name',
        other: 'params',
      }
    case 'TLSA':
      return {
        weight: 'certificate usage',
        priority: 'selector',
        address: 'certificate association data',
        other: 'matching type',
      }
    case 'TXT':
      return { address: 'data' }
    case 'URI':
      return { address: 'target' }
    default:
      // Types NicTool stores without column overloading need no translation.
      return {}
  }
}

function applyMap(obj, map) {
  // map dns-r-r (RFC/IETF) field names to NicTool 2.0 DB fields

  for (const [key, value] of mapEntries(map)) {
    if (Array.isArray(value)) {
      obj[key] = `'${value.map((a) => obj[a]).join("','")}'`;
      for (const f of value) {
        delete obj[f];
      }
      // No `delete obj[value]` here: an array key stringifies to
      // "flags,service,regexp" and would delete an unrelated property.
      continue
    }

    obj[key] = obj[value];
    delete obj[value];
  }
}

// Integers on the wire. `certtype` is numeric but also accepts mnemonics
// ("PKIX"), so a value is converted only when it actually looks numeric —
// the declared format alone is not enough.
const NUMERIC_FORMATS = new Set(['u8', 'u16', 'u32', 'certtype', 'rrtype']);

/**
 * type -> the fields that class declares as integers, from its static
 * rdataFields. NicTool's `other` column is VARCHAR, so MySQL hands back "1"
 * where the RR setter demands an integer; `weight` and `priority` are SMALLINT
 * and only arrive as strings from a file store or hand-edited data.
 *
 * Keyed on the type because a bare field name is ambiguous: `flags` is u8 in
 * CAA, u16 in DNSKEY and a character string in NAPTR.
 *
 * Populated by index.js, which is where the classes are already enumerated;
 * importing them here would close an import cycle.
 */
const numericFields = new Map();

function registerRdataFormats(classes) {
  for (const rrClass of classes) {
    const numeric = new Set();
    for (const entry of rrClass.rdataFields ?? []) {
      if (Array.isArray(entry) && NUMERIC_FORMATS.has(entry[1])) numeric.add(entry[0]);
    }
    numericFields.set(rrClass.typeName, numeric);
  }
}

function unApplyMap(obj, map) {
  // map NicTool 2.0 DB fields to dns-r-r (RFC/IETF) field names
  let packed = false;

  if (obj.type === 'NAPTR') {
    const [flags, service, regexp] = obj.address.slice(1, -1).split("','");
    obj.flags = flags ?? '';
    obj.service = service ?? '';
    obj.regexp = regexp ?? '';
    delete obj.address;
    packed = true;
  }
  if (obj.type === 'NSEC3') {
    const [algo, flags, iters, salt, bitmaps, next] = obj.address.slice(1, -1).split("','");
    obj['hash algorithm'] = /^\d+$/.test(algo) ? parseInt(algo, 10) : (algo ?? '');
    obj.flags = /^\d+$/.test(flags) ? parseInt(flags, 10) : (flags ?? '');
    obj.iterations = /^\d+$/.test(iters) ? parseInt(iters, 10) : (iters ?? '');
    obj.salt = salt;
    obj['type bit maps'] = bitmaps;
    obj['next hashed owner name'] = next;
    delete obj.address;
    packed = true;
  }
  if (obj.type === 'NSEC3PARAM') {
    const [algo, flags, iters, salt] = obj.address.slice(1, -1).split("','");
    obj['hash algorithm'] = /^\d+$/.test(algo) ? parseInt(algo, 10) : (algo ?? '');
    obj.flags = /^\d+$/.test(flags) ? parseInt(flags, 10) : (flags ?? '');
    obj.iterations = /^\d+$/.test(iters) ? parseInt(iters, 10) : (iters ?? '');
    obj.salt = salt;
    delete obj.address;
    packed = true;
  }
  if (obj.type === 'SOA') {
    const [one, two, three, four, five, six, seven] = obj.address.slice(1, -1).split("','");
    obj.mname = one;
    obj.rname = two;
    obj.serial = parseInt(three, 10);
    obj.refresh = parseInt(four, 10);
    obj.retry = parseInt(five, 10);
    obj.expire = parseInt(six, 10);
    obj.minimum = parseInt(seven, 10);
    delete obj.address;
    packed = true;
  }

  const numeric = numericFields.get(obj.type);

  for (const [key, value] of mapEntries(map)) {
    if (packed && key === 'address') continue
    const stored = obj[key];
    // Only a string can need converting, and skipping the rest keeps the
    // numeric columns MySQL already types correctly off this path entirely.
    obj[value] =
      typeof stored === 'string' && numeric?.has(value) && /^\d+$/.test(stored)
        ? parseInt(stored, 10)
        : stored;
    delete obj[key];
  }
}

// RFC 1035 §5.1 master-file lexer. Escapes stay in token text because their
// meaning depends on the field: in a name, `\.` is a dot inside a label.
// `"`, `(` and `)` delimit tokens even without whitespace, as in BIND. A token
// that touches the one before it is marked `adjoins`, so SVCB's key="value"
// survives as one parameter.
function tokenize(line) {
  const tokens = [];
  let token = null;
  let depth = 0;
  let separated = true;
  const start = (quoted) => {
    token = separated ? { text: '', quoted } : { text: '', quoted, adjoins: true };
    separated = false;
  };
  const flush = () => {
    if (token) tokens.push(token);
    token = null;
  };
  const separate = () => {
    flush();
    separated = true;
  };

  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '\\') {
      if (i + 1 === line.length) throw new Error('BIND: incomplete escape')
      if (!token) start(false);
      token.text += c + line[++i];
    } else if (c === '"') {
      flush();
      start(true);
      for (i++; line[i] !== '"'; i++) {
        if (i >= line.length) throw new Error('BIND: unterminated quoted string')
        if (line[i] === '\n') throw new Error('BIND: newline in quoted string')
        if (line[i] === '\\') {
          if (i + 1 === line.length) throw new Error('BIND: incomplete escape')
          token.text += line[i++];
        }
        token.text += line[i];
      }
      flush();
    } else if (c === ';') {
      separate();
      while (i + 1 < line.length && line[i + 1] !== '\n') i++;
    } else if (c === '(' || c === ')') {
      separate();
      depth += c === '(' ? 1 : -1;
      if (depth < 0) throw new Error('BIND: unbalanced parentheses')
    } else if (c === '\n' && depth === 0) {
      separate();
      if (/\S/.test(line.slice(i + 1))) throw new Error('BIND: text after end of record')
    } else if (/\s/.test(c)) {
      separate();
    } else {
      if (!token) start(false);
      token.text += c;
    }
  }
  flush();
  if (depth !== 0) throw new Error('BIND: unbalanced parentheses')
  return tokens
}

function parseBindLine(line, RRClasses) {
  const res = {
    class: 'IN',
    type: '',
    rdata: [],
  };

  const tokens = tokenize(line);
  if (tokens.length < 1) return null

  if (!/^\s/.test(line)) {
    res.owner = tokens.shift().text;
  }

  while (tokens.length > 0) {
    const token = tokens[0].text.toUpperCase();

    if (RRClasses[token]) {
      res.class = tokens.shift().text.toUpperCase();
      continue
    }

    if (/^CLASS\d+$/.test(token)) {
      // RFC 3597 §5 unknown-class syntax; setClass validates the number
      res.class = tokens.shift().text.toUpperCase();
      continue
    }

    if (/^\d+$/.test(token)) {
      res.ttl = parseInt(tokens.shift().text, 10);
      continue
    }

    res.type = tokens.shift().text.toUpperCase();
    break
  }

  res.rdata = tokens;

  return res
}

// RFC 1035 §5.1: \DDD is an octet, \X is X. Octets must form UTF-8
function decodeCharString(text) {
  let bytes;
  try {
    bytes = presentationBytes(text);
  } catch (e) {
    throw new Error(`BIND: ${e.message}`, { cause: e })
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    throw new Error(`BIND: character-string is not UTF-8: ${text}`)
  }
}

// Controls are written as \DDD so the quoted string stays on one line.
function escapeCharString(str) {
  return Array.from(String(str), (c) => {
    if (c === '"' || c === '\\') return `\\${c}`
    const code = c.codePointAt(0);
    return code < 0x20 || code === 0x7f ? `\\${String(code).padStart(3, '0')}` : c
  }).join('')
}

// A list field is the rest of the rdata, kept in presentation form for the
// RR's own setter to parse: type bit maps, APL items, SVCB params.
const listTypes = new Set(['list', 'svcparams']);

function joinList(tokens) {
  return tokens
    .map((t) => (t.adjoins ? '' : ' ') + (t.quoted ? `"${t.text}"` : t.text))
    .join('')
    .trimStart()
}

function fieldTypeOf(def) {
  return Array.isArray(def) ? def[1] : null
}

// RFC 3597 §5 generic rdata: '\# <length> <hex words>', parens permitted.
// Every word must contain an even number of hex digits, not just the whole.
function parseGenericRdata(tokens) {
  const words = tokens.filter((w) => w !== '(' && w !== ')');
  if (words[0] !== '\\#') throw new Error(`RFC 3597: generic rdata must begin with \\#`)
  if (!/^\d+$/.test(words[1] ?? '') || parseInt(words[1], 10) > 65535)
    throw new Error(`RFC 3597: invalid rdata length: ${words[1]}`)
  const length = parseInt(words[1], 10);
  for (const w of words.slice(2)) {
    if (!/^[0-9a-fA-F]+$/.test(w) || w.length % 2 !== 0)
      throw new Error(`RFC 3597: each rdata word must be an even number of hex digits: ${w}`)
  }
  const hex = words.slice(2).join('').toLowerCase();
  if (hex.length !== length * 2)
    throw new Error(`RFC 3597: rdata length mismatch: declared ${length}, got ${hex.length / 2} bytes`)
  return { length, hex }
}

// An RR of known type in generic form MUST be processed as the known type
// (RFC 3597 §5), so the hex is decoded through the class's wire parser.
function fromBind3597(rrInstance, parsed) {
  const { hex } = parseGenericRdata(parsed.rdata.map((t) => t.text));
  const staticId = rrInstance.constructor.typeId;
  const typeId = typeNameToId(parsed.type); // 'TYPE731', 'AFSDB', ...; garbage throws
  if (staticId !== undefined && typeId !== staticId)
    throw new Error(`${rrInstance.constructor.typeName}: ${parsed.type} does not match type id ${staticId}`)
  const rdata = hexToBytes(hex);
  const rr = rrInstance.fromWire({
    owner: parsed.owner,
    cls: parsed.class,
    ttl: parsed.ttl,
    rdata,
    typeId: typeId ?? staticId,
  });
  assertWireRoundTrip(rr, rdata);
  return rr
}

// UNKNOWN has no static typeId and accepts any TYPEnnn.
function assertType(type, RRClass) {
  if (RRClass.typeId === undefined || type === RRClass.typeName) return
  if (!type) throw new Error(`expected ${RRClass.typeName}, got no type`)
  const typeNN = type.match(/^TYPE(\d+)$/);
  if (typeNN !== null && Number(typeNN[1]) === RRClass.typeId) return
  throw new Error(`expected ${RRClass.typeName}, got ${type}`)
}

function fromBind(rrInstance, opts) {
  const { owner, ttl, class: cls, rdata } = opts;
  const typeName = rrInstance.constructor.typeName;
  const result = {
    owner,
    ttl,
    class: cls,
    type: typeName,
  };

  const fields = rrInstance.getFields('rdata');
  const rdataDefs = rrInstance.constructor.rdataFields ?? [];
  const opaqueTypes = new Set(['str', 'hex', 'base64']);
  const lastType = fieldTypeOf(rdataDefs.at(-1));
  const lastIsList = listTypes.has(lastType);

  const required = lastIsList ? fields.length - 1 : fields.length;
  if (rdata.length < required)
    throw new Error(`${typeName}: missing rdata: ${fields.slice(rdata.length).join(', ')}`)
  const lastIsVariadic = opaqueTypes.has(lastType) || lastType === 'charstrs' || lastIsList;
  if (rdata.length > fields.length && !lastIsVariadic)
    throw new Error(
      `${typeName}: unexpected rdata: ${rdata
        .slice(fields.length)
        .map((t) => t.text)
        .join(' ')}`,
    )
  for (let i = 0; i < fields.length; i++) {
    const isLastField = i === fields.length - 1;

    // RFC 1035 §5.1: opaque rdata (hex digests, base64 keys) may be split across
    // whitespace and parenthesized continuations; rejoin it into one value.
    if (isLastField && opaqueTypes.has(fieldTypeOf(rdataDefs[i]))) {
      result[fields[i]] = rdata
        .slice(i)
        .map((t) => t.text)
        .join('');
      break
    }

    if (isLastField && lastIsList) {
      result[fields[i]] = joinList(rdata.slice(i));
      break
    }

    // RFC 1035 §3.3.14: TXT keeps its character-string boundaries.
    if (isLastField && fieldTypeOf(rdataDefs[i]) === 'charstrs') {
      const strings = rdata.slice(i).map((t) => decodeCharString(t.text));
      result[fields[i]] = strings.length > 1 ? strings : strings[0];
      break
    }

    let val = rdata[i]?.text;
    if (rrInstance.isQuotedField(fields[i])) {
      val = val === undefined ? undefined : decodeCharString(val);
    } else if (NUMERIC_FORMATS.has(fieldTypeOf(rdataDefs[i])) && /^\d+$/.test(val)) {
      val = parseInt(val, 10);
    }
    result[fields[i]] = val;
  }

  return new rrInstance.constructor(result)
}

function toBind(rrInstance, zone_opts) {
  const rdata = (rrInstance.constructor.rdataFields ?? [])
    .map((def) => {
      const f = Array.isArray(def) ? def[0] : def;
      if (rrInstance.isFqdnField(f)) return rrInstance.getFQDN(f, zone_opts)
      if (rrInstance.isQuotedField(f)) return `"${escapeCharString(rrInstance.get(f))}"`
      // RFC 4034 §3.2: a type is presented as its mnemonic, or TYPEnnn (RFC 3597).
      if (fieldTypeOf(def) === 'rrtype') return typeIdToName(rrInstance.get(f))
      return rrInstance.get(f)
    })
    .join('\t');
  return `${rrInstance.getPrefix(zone_opts)}\t${rdata}\n`
}

const customInspect = Symbol.for('nodejs.util.inspect.custom');

class RR {
  static CLASSES = { IN: 1, CS: 2, CH: 3, HS: 4, NONE: 254, ANY: 255 }
  static typeId
  static RFCs = []
  static tags = []

  constructor(opts) {
    if (opts === null) return

    if (opts?.default) this.default = opts.default;

    // tinydns specific
    this.setLocation(opts?.location);
    this.setTimestamp(opts?.timestamp);

    this.setOwner(opts?.owner);
    this.setType(opts?.type);
    this.setTtl(opts?.ttl);
    this.setClass(opts?.class);

    for (const entry of this.constructor.rdataFields ?? []) {
      const f = RR.fieldName(entry);
      const fieldType = Array.isArray(entry) ? entry[1] : null;
      const fnName = `set${this.ucFirst(f)}`;
      if (typeof this[fnName] === 'function') {
        this[fnName](opts?.[f]);
      } else if (fieldType) {
        this.setTypedValue(fieldType, f, opts?.[f]);
      } else {
        this.set(f, opts?.[f]);
      }
    }

    if (opts?.comment) this.set('comment', opts.comment);
  }

  static fromBind(line, opts = {}) {
    const instance = new this(null);
    if (opts.default !== undefined) instance.default = opts.default;
    const parsed = this.parseBindLine(line);
    if (!parsed) return null
    if (parsed.rdata[0]?.text === '\\#' && !parsed.rdata[0].quoted) return fromBind3597(instance, parsed) // RFC 3597 §5
    assertType(parsed.type, this);
    return instance.fromBind({ ...opts, ...parsed })
  }

  fromBind(opts) {
    return fromBind(this, opts)
  }

  static parseBindLine(line) {
    return parseBindLine(line, RR.CLASSES)
  }

  static fromTinydns(line, opts = {}) {
    const instance = new this(null);
    if (opts.default !== undefined) instance.default = opts.default;
    return instance.fromTinydns({ ...opts, tinyline: line })
  }

  fromTinydns(opts) {
    if (this.constructor.tinydnsType) return fromGeneric(this, opts)
    return this.fromTinydnsWire(opts)
  }

  // A generic `:` line is the type number and the wire rdata, octal-escaped.
  fromTinydnsWire({ tinyline }) {
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline);
    if (Number(typeId) !== this.getTypeId())
      this.throwHelp(`${this.constructor.typeName} fromTinydns: type ${typeId} is not ${this.getTypeId()}`);
    const rr = this.fromWire({
      owner,
      cls: 'IN',
      ttl,
      rdata: octalRdataToBytes(rdata ?? ''),
      typeId: Number(typeId),
    });
    rr.setTimestamp(timestamp);
    rr.setLocation(location);
    return rr
  }

  static fromWire(wireBytes) {
    return fromWireBytes(this, wireBytes, wireUnpackDomain)
  }

  fromWire(opts) {
    return fromWireGeneric(this, opts)
  }

  static #reserved = ['__proto__', 'constructor', 'prototype']

  get(key) {
    if (RR.#reserved.includes(key)) throw new Error(`Invalid field name: ${key}`)
    return this[key]
  }

  set(key, value) {
    if (RR.#reserved.includes(key)) throw new Error(`Invalid field name: ${key}`)
    this[key] = value;
    return this
  }

  toJSON() {
    const fields = [...this.getFields(), 'location', 'timestamp', 'comment'];
    const obj = {};
    for (const f of fields) {
      const v = this.get(f);
      if (v !== undefined) obj[f] = v;
    }
    return obj
  }

  [customInspect](depth, options, nextInspect) {
    // Returns a formatted string that looks like: A { ... }
    return `${this.type} ${nextInspect(this.toJSON(), options)}`
  }

  ucFirst(str) {
    if (!str) return str
    return str
      .split(/\s/)
      .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
      .join('')
  }

  setClass(c) {
    if ([undefined, null, ''].includes(c)) {
      this.set('class', 'IN');
      return
    }
    if (RR.CLASSES[c.toUpperCase()]) {
      this.set('class', c.toUpperCase());
      return
    }
    const generic = c.toUpperCase().match(/^CLASS(\d+)$/); // RFC 3597 §5
    if (generic && parseInt(generic[1], 10) <= 65535) {
      const id = parseInt(generic[1], 10);
      const known = Object.keys(RR.CLASSES).find((k) => RR.CLASSES[k] === id);
      this.set('class', known ?? `CLASS${id}`);
      return
    }
    this.throwHelp(`invalid class ${c}`);
  }

  setLocation(l) {
    switch (l) {
      case undefined:
        return
      default:
        this.set('location', l);
    }
  }

  setTimestamp(l) {
    switch (l) {
      case undefined:
        return
      default:
        this.set('timestamp', l);
    }
  }

  setOwner(n) {
    if (n === undefined || n === '') this.throwHelp(`owner is required`);

    const typeName = this.constructor.typeName ?? this.constructor.name;
    this.isFullyQualified(typeName, 'owner', n);
    this.isValidName(typeName, 'owner', n);

    // RFC 4592: a wildcard is a leftmost label of exactly `*`. An escaped \* or
    // \042 is a literal byte and may appear anywhere.
    const unescaped = n.replace(/\\(?:[0-9]{3}|.)/g, '_');
    if (unescaped.split('.').some((label, i) => label.includes('*') && (label !== '*' || i > 0)))
      this.throwHelp('only *.something or * (by itself) is a valid wildcard');

    this.set('owner', lowercaseName(n));
  }

  setTtl(t) {
    t = t ?? this.default?.ttl;
    if (t === undefined) {
      if (['SOA', 'SSHFP', 'RRSIG'].includes(this.get('type'))) return
      this.throwHelp('TTL is required, no default available');
    }

    if (typeof t !== 'number') this.throwHelp(`TTL must be numeric (${typeof t})`);

    // RFC 2181 §8: the high bit is reserved, so a TTL is 0 to 2^31 - 1.
    if (!Number.isInteger(t) || t < 0 || t > 2147483647)
      this.throwHelp(`TTL must be an integer from 0 to 2147483647 (RFC 2181 §8)`);

    this.set('ttl', t);
  }

  setType(t) {
    if ([undefined, ''].includes(t)) t = this.constructor.typeName;

    if (t === undefined) this.throwHelp(`type is required`);

    if (t.toUpperCase() !== this.constructor.typeName)
      this.throwHelp(`type ${t} doesn't match ${this.constructor.typeName}`);

    this.set('type', t.toUpperCase());
  }

  throwHelp(e) {
    if (!this.constructor.typeName) throw new Error(e)

    const typeName = this.constructor.typeName;
    const example = this.getCanonical
      ? `Example ${typeName}:\n${JSON.stringify(this.getCanonical(), null, '\t')}\n\n`
      : `${typeName} records have the fields: ${this.getFields().join(', ')}\n\n`;

    throw new Error(`${e}\n\n${example}${this.citeRFC()}\n`)
  }

  citeRFC() {
    return `see RFC${this.getRFCs().length > 1 ? 's' : ''} ${this.getRFCs()}`
  }

  fullyQualify(hostname, origin) {
    if (!hostname) return hostname
    if (hostname === '@' && origin) hostname = origin;
    if (hostname.endsWith('.')) return lowercaseName(hostname)
    if (origin) return lowercaseName(`${hostname}.${origin}`)
    return `${hostname}.`
  }

  getPrefix(zone_opts = {}) {
    const classVal = zone_opts.hide?.class ? '' : this.get('class');

    let rrTTL = this.get('ttl');
    if (zone_opts.hide?.ttl && rrTTL === zone_opts.ttl) rrTTL = '';

    let owner = this.get('owner');
    if (zone_opts.hide?.sameOwner && zone_opts.previousOwner === owner) {
      owner = '';
    } else {
      owner = this.getFQDN('owner', zone_opts);
    }

    return `${owner}\t${rrTTL}\t${classVal}\t${this.get('type')}`
  }

  getEmpty(prop) {
    return this.get(prop) ?? ''
  }

  getComment(prop) {
    const c = this.get('comment');
    if (!c || !c[prop]) return ''
    return c[prop]
  }

  getQuoted(prop) {
    if (!this.isQuotedField(prop)) return this.get(prop)
    return quoteCharString(this.get(prop))
  }

  static fieldName(entry) {
    return Array.isArray(entry) ? entry[0] : entry
  }

  static fieldType(entry) {
    return Array.isArray(entry) ? entry[1] : null
  }

  getRdataFields() {
    return (this.constructor.rdataFields ?? []).map((e) => RR.fieldName(e))
  }

  getTags() {
    return this.constructor.tags ?? []
  }

  getRFCs() {
    return this.constructor.RFCs ?? []
  }

  getTypeId() {
    const typeId = this.constructor.typeId;
    if (typeId === undefined) this.throwHelp(`${this.constructor.typeName}: missing static typeId`);
    return typeId
  }

  static getTypeId() {
    return this.typeId
  }

  getClassId() {
    const c = this.get('class');
    return RR.CLASSES[c] ?? parseInt(c.slice(5), 10) // 'CLASS32' -> 32
  }

  getFields(arg) {
    const commonFields = ['owner', 'ttl', 'class', 'type'];
    Object.freeze(commonFields);

    const rdataFields = this.getRdataFields();

    switch (arg) {
      case 'common':
        return commonFields
      case 'rdata':
        return rdataFields
      default:
        return commonFields.concat(rdataFields)
    }
  }

  getFQDN(field, zone_opts = {}) {
    let fqdn = this.get(field);
    if (!fqdn) this.throwHelp(`empty value for field ${field}`);
    if (!fqdn.endsWith('.')) fqdn += '.';

    if (zone_opts.hide?.origin && zone_opts.origin) {
      if (fqdn === zone_opts.origin) return '@'
      if (fqdn.endsWith(zone_opts.origin)) return fqdn.slice(0, fqdn.length - zone_opts.origin.length - 1)
    }

    return fqdn
  }

  getTinyFQDN(field) {
    const val = this.get(field);
    if (val === '') return val // empty
    if (val === '.') return val // null MX

    // strip off trailing ., tinydns doesn't require it for FQDN
    if (val.endsWith('.')) return val.slice(0, -1)

    return val
  }

  getTinydnsGeneric(rdata) {
    return `:${this.getTinyFQDN('owner')}:${this.getTypeId()}:${rdata}:${this.getTinydnsPostamble()}\n`
  }

  getTinydnsPostamble() {
    // every tinydns line ends with this, making it the choke point for the
    // class guard: tinydns data files have no class field
    this.assertClassIN('tinydns');
    return ['ttl', 'timestamp', 'location'].map((f) => this.getEmpty(f)).join(':')
  }

  assertClassIN(format) {
    if (this.get('class') !== 'IN')
      this.throwHelp(`${format} supports only class IN, got ${this.get('class')}`);
  }

  // RFC 2181 §11: any binary string can be a label, 1-63 octets, and the
  // name 255 octets on the wire, length octets and root included.
  hasValidLabels(hostname) {
    let labels;
    try {
      labels = nameToLabels(hostname);
    } catch (e) {
      this.throwHelp(`${e.message}, RFC 2181`);
    }
    const wireLength = labels.reduce((n, label) => n + 1 + label.length, 1);
    if (wireLength > 255) this.throwHelp(`Domain names must have 1-255 octets, got ${wireLength}: RFC 2181`);
  }

  is8bitInt(type, field, value) {
    if (Number.isInteger(value) && value >= 0 && value <= 255) return true

    this.throwHelp(`${type} ${field} must be a 8-bit integer (in the range 0-255)`);
  }

  is16bitInt(type, field, value) {
    if (Number.isInteger(value) && value >= 0 && value <= 65535) return true

    this.throwHelp(`${type} ${field} must be a 16-bit integer (in the range 0-65535)`);
  }

  is32bitInt(type, field, value) {
    if (Number.isInteger(value) && value >= 0 && value <= 4294967295) return true

    this.throwHelp(`${type} ${field} must be a 32-bit integer (in the range 0-4294967295)`);
  }

  // RFC 4034 §3.2: a signature time is epoch seconds or YYYYMMDDHHmmSS in UTC.
  // Fourteen digits always exceed 32 bits, so the two forms cannot collide.
  setSignatureTime(field, val) {
    const date = String(val).match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/);
    if (date) {
      const ms = Date.UTC(date[1], date[2] - 1, date[3], date[4], date[5], date[6]);
      if (formatSignatureTime(ms / 1000) !== date[0])
        this.throwHelp(`${this.constructor.typeName} ${field} is not a valid date: ${val}`);
      // modulo 2^32, so a date before 1970 wraps into the unsigned range
      val = (((ms / 1000) % 2 ** 32) + 2 ** 32) % 2 ** 32;
    }
    this.is32bitInt(this.constructor.typeName, field, val);
    this.set(field, val);
  }

  // Hex octets, of an exact length when the field's algorithm fixes one.
  isHexDigest(field, value, bytes) {
    const typeName = this.constructor.typeName;
    if (typeof value !== 'string' || !/^([0-9a-fA-F]{2})+$/.test(value))
      this.throwHelp(`${typeName}: ${field} must be hex octets`);
    if (bytes !== undefined && value.length !== bytes * 2)
      this.throwHelp(`${typeName}: ${field} must be ${bytes} bytes, got ${value.length / 2}`);
  }

  isBase64(type, field, value) {
    if (
      typeof value === 'string' &&
      value.length > 0 &&
      value.length % 4 === 0 &&
      /^[A-Za-z0-9+/]*={0,2}$/.test(value)
    )
      return true

    this.throwHelp(`${type} ${field} must be a valid base64 string`);
  }

  isQuoted(val) {
    return /^["']/.test(val) && /["']$/.test(val)
  }

  setFqdnValue(typeName, fieldName, val) {
    if (!val) this.throwHelp(`${typeName}: ${fieldName} is required`);
    if (this.isIPv4(val) || this.isIPv6(val))
      this.throwHelp(`${typeName}: ${fieldName} must be a domain name`);
    this.isFullyQualified(typeName, fieldName, val);
    this.isValidName(typeName, fieldName, val);
    this.set(fieldName, lowercaseName(val));
  }

  setTypedValue(type, fieldName, val) {
    const typeName = this.constructor.typeName;
    switch (type) {
      case 'u8':
        this.is8bitInt(typeName, fieldName, val);
        this.set(fieldName, parseInt(val, 10));
        break
      case 'u16':
        this.is16bitInt(typeName, fieldName, val);
        this.set(fieldName, parseInt(val, 10));
        break
      case 'rrtype':
        try {
          this.set(fieldName, typeNameToId(val));
        } catch {
          this.throwHelp(`${typeName}: ${fieldName} is not a type name, TYPEnnn, or 0-65535`);
        }
        break
      case 'certtype': {
        if (val === undefined || val === null || val === '')
          this.throwHelp(`${typeName}: ${fieldName} is required`);
        if (typeof val === 'string' && !/^[0-9]+$/.test(val)) {
          const certTypes = this.constructor.CERT_TYPES;
          if (!certTypes || !Object.hasOwn(certTypes, val)) {
            this.throwHelp(`${typeName}: unknown cert type mnemonic: ${val}`);
          }
          this.set(fieldName, val);
          break
        }
        this.is16bitInt(typeName, fieldName, val);
        this.set(fieldName, parseInt(val, 10));
        break
      }
      case 'u32':
        this.is32bitInt(typeName, fieldName, val);
        this.set(fieldName, parseInt(val, 10));
        break
      case 'fqdn':
        this.setFqdnValue(typeName, fieldName, val);
        break
      case 'base64':
        this.isBase64(typeName, fieldName, val);
        this.set(fieldName, val);
        break
      case 'hex':
        if (!/^[0-9a-fA-F]*$/.test(val)) this.throwHelp(`${typeName}: ${fieldName} must be hexadecimal`);
        this.set(fieldName, val);
        break
      case 'str':
        if (!val) this.throwHelp(`${typeName}: ${fieldName} is required`);
        this.set(fieldName, val);
        break
      case 'qstr':
        if (val === undefined || val === null) this.throwHelp(`${typeName}: ${fieldName} is required`);
        this.set(fieldName, val);
        break
      case 'charstr': {
        if (val === undefined || val === null) this.throwHelp(`${typeName}: ${fieldName} is required`);
        const value = String(val);
        const byteLen = new TextEncoder().encode(value).length;
        if (byteLen > 255) this.throwHelp(`${typeName}: ${fieldName} must be <=255 bytes`);
        this.set(fieldName, value);
        break
      }
      case 'qcharstr': {
        if (val === undefined || val === null) this.throwHelp(`${typeName}: ${fieldName} is required`);
        const value = String(val);
        const byteLen = new TextEncoder().encode(value).length;
        if (byteLen > 255) this.throwHelp(`${typeName}: ${fieldName} must be <=255 bytes`);
        this.set(fieldName, value);
        break
      }
      case 'charstrs':
        if (val === undefined || val === null) this.throwHelp(`${typeName}: ${fieldName} is required`);
        this.set(fieldName, val);
        break
      case 'svcparams':
        this.setSvcParams(fieldName, val ?? '');
        break
      case 'list':
        this.set(fieldName, val ?? '');
        break
      case 'ipv4':
        if (!this.isIPv4(val)) this.throwHelp(`${typeName}: ${fieldName} must be a valid IPv4 address`);
        this.set(fieldName, val);
        break
      case 'ipv6':
        if (!this.isIPv6(val)) this.throwHelp(`${typeName}: ${fieldName} must be a valid IPv6 address`);
        this.set(fieldName, this.expandIPv6(val.toLowerCase())); // lower case: RFC 5952
        break
    }
  }

  setSvcParams(fieldName, val) {
    const typeName = this.constructor.typeName;
    let keys;
    try {
      keys = svcParamKeyIds(val);
    } catch (e) {
      this.throwHelp(`${typeName}: ${e.message.replace(/^SVCB: /, '')}`);
    }
    // RFC 9460 §2.4.2: BIND rejects params in AliasMode.
    if (this.get('priority') === 0 && keys.length)
      this.throwHelp(`${typeName}: AliasMode (priority 0) takes no params`);
    // RFC 9460 §7.1.1
    if (keys.includes(2) && !keys.includes(1)) this.throwHelp(`${typeName}: no-default-alpn requires alpn`);
    // RFC 9460 §8: every mandatory key must be present.
    const mandatory = val.match(/(?:^|\s)mandatory="?([^"\s]+)/)?.[1];
    if (mandatory) {
      const missing = mandatory.split(',').filter((k) => !keys.includes(svcParamKeyId(k.toLowerCase())));
      if (missing.length) this.throwHelp(`${typeName}: mandatory keys missing: ${missing.join(', ')}`);
    }
    // Stored in the form the wire decodes to, so equal params compare equal.
    this.set(fieldName, svcParamsFromWire(svcParamsToWire(val)));
  }

  lowercaseName(name) {
    return lowercaseName(name)
  }

  isFullyQualified(type, field, hostname) {
    if (hostname.endsWith('.')) return true

    this.throwHelp(`${type}: ${field} must be fully qualified`);
  }

  isValidName(type, field, hostname) {
    this.hasValidLabels(hostname);
    // Names are stored in presentation form, so master-file delimiters
    // must arrive escaped (\032, \;) or the BIND export splits the name.
    if (/[\s;"()]/.test(hostname.replace(/\\(?:[0-9]{3}|.)/g, '_')))
      this.throwHelp(`${type}: ${field} has an unescaped delimiter: ${hostname}`);
    return true
  }

  isIPv4(string) {
    // https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp
    return /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/.test(string)
  }

  isIPv6(string) {
    return /^(?:(?:[a-fA-F\d]{1,4}:){7}(?:[a-fA-F\d]{1,4}|:)|(?:[a-fA-F\d]{1,4}:){6}(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|:[a-fA-F\d]{1,4}|:)|(?:[a-fA-F\d]{1,4}:){5}(?::(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,2}|:)|(?:[a-fA-F\d]{1,4}:){4}(?:(?::[a-fA-F\d]{1,4}){0,1}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,3}|:)|(?:[a-fA-F\d]{1,4}:){3}(?:(?::[a-fA-F\d]{1,4}){0,2}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,4}|:)|(?:[a-fA-F\d]{1,4}:){2}(?:(?::[a-fA-F\d]{1,4}){0,3}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,5}|:)|(?:[a-fA-F\d]{1,4}:){1}(?:(?::[a-fA-F\d]{1,4}){0,4}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,6}|:)|(?::(?:(?::[a-fA-F\d]{1,4}){0,5}:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}|(?::[a-fA-F\d]{1,4}){1,7}|:)))(?:%[0-9a-zA-Z]{1,})?$/gm.test(
      string,
    )
  }

  expandIPv6(val, delimiter) {
    return expandIPv6(val, delimiter)
  }

  compressIPv6(val) {
    //  * RFC 5952
    //  * 4.1. Leading zeros MUST be suppressed...A single 16-bit 0000 field MUST be represented as 0.
    //  * 4.2.1 The use of the symbol "::" MUST be used to its maximum capability.
    //  * 4.2.2 The symbol "::" MUST NOT be used to shorten just one 16-bit 0 field.
    //  * 4.2.3 When choosing placement of a "::", the longest run...MUST be shortened
    //  * 4.3 The characters a-f in an IPv6 address MUST be represented in lowercase.

    // 4.3 Lowercase and 4.1 remove leading zeros per segment
    const segments = val
      .toLowerCase()
      .split(':')
      .map((s) => s.replace(/^0+/, '') || '0');

    let bestStart = -1;
    let bestLen = 0;
    let curStart = -1;
    let curLen = 0;

    // 4.2.1 & 4.2.3 Find the longest consecutive run of '0'
    for (let i = 0; i < segments.length; i++) {
      if (segments[i] === '0') {
        if (curStart === -1) curStart = i;
        curLen++;
        if (curLen > bestLen) {
          bestLen = curLen;
          bestStart = curStart;
        }
      } else {
        curStart = -1;
        curLen = 0;
      }
    }

    // 4.2.2 Don't shorten a single 16-bit 0 field
    if (bestLen < 2) {
      return segments.join(':')
    }

    const head = segments.slice(0, bestStart).join(':');
    const tail = segments.slice(bestStart + bestLen).join(':');

    return `${head}::${tail}`
  }

  octalToUint8Array(octalStr) {
    const str = octalToChar(octalStr);
    return Uint8Array.from(str, (c) => c.charCodeAt(0))
  }

  wireUnpackDomain(bytes, offset = 0) {
    return wireUnpackDomain(bytes, offset)
  }

  wirePackDomain(fqdn) {
    return wirePackDomain(fqdn)
  }

  getWireRdata() {
    return getWireRdata(this)
  }

  toWire() {
    return toWire(this)
  }

  toBind(zone_opts) {
    return toBind(this, zone_opts)
  }

  parseTinydnsLine(tinyline) {
    const parsed = parseGenericLine(tinyline);
    return { ...parsed, owner: this.fullyQualify(parsed.owner) }
  }

  toTinydns() {
    return to(this)
  }

  isFqdnField(field) {
    return (
      (this.constructor.rdataFields ?? []).some(
        (entry) => RR.fieldName(entry) === field && RR.fieldType(entry) === 'fqdn',
      ) || false
    )
  }

  isQuotedField(field) {
    const quotedTypes = new Set(['qstr', 'qcharstr', 'charstrs']);
    return (
      (this.constructor.rdataFields ?? []).some(
        (entry) => RR.fieldName(entry) === field && quotedTypes.has(RR.fieldType(entry)),
      ) || false
    )
  }

  toMaraDNS() {
    // MaraDNS csv2 zone files have no class field either
    this.assertClassIN('MaraDNS');
    const type = this.get('type');
    const supportedTypes = 'A PTR MX AAAA SRV NAPTR NS SOA TXT SPF RAW FQDN4 FQDN6 CNAME HINFO WKS LOC'.split(
      /\s+/g,
    );
    if (!supportedTypes.includes(type)) return this.toMaraGeneric()
    // csv2's MX and NAPTR parsers reject a bare '.' (the root) as a name.
    const fields = this.getFields('rdata');
    if (fields.some((f) => this.isFqdnField(f) && this.get(f) === '.')) return this.toMaraGeneric()
    // csv2 separates adjacent character-strings with ';' (HINFO, NAPTR).
    const rdata = fields
      .map((f, i) => {
        const sep = i === 0 ? '' : this.isQuotedField(f) && this.isQuotedField(fields[i - 1]) ? ';' : '\t';
        return sep + this.getQuoted(f)
      })
      .join('');
    return `${this.get('owner')}\t+${this.get('ttl')}\t${type}\t${rdata} ~\n`
  }

  toMaraGeneric() {
    this.assertClassIN('MaraDNS');
    // csv2 refuses these types even as RAW.
    if (['A6', 'DNAME', 'OPT'].includes(this.get('type')))
      this.throwHelp(`MaraDNS does not support ${this.get('type')} records`);
    // MaraDNS csv2 interprets \xNN escapes only outside quoted text, so every
    // rdata byte is emitted as an unquoted escape. '' is zero-length rdata.
    const bytes = this.getWireRdata();
    const rdata = bytes.length
      ? [...bytes].map((b) => `\\x${b.toString(16).padStart(2, '0')}`).join('')
      : `''`;
    return `${this.get('owner')}\t+${this.get('ttl')}\tRAW ${this.getTypeId()}\t${rdata} ~\n`
  }
}

function formatSignatureTime(seconds) {
  return new Date(seconds * 1000).toISOString().replace(/\D/g, '').slice(0, 14)
}

class A extends RR {
  static typeName = 'A'
  static typeId = 1
  static RFCs = [1035]
  static tinydnsType = '+'
  static rdataFields = [['address', 'ipv4']]
  static tags = ['common']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setAddress(val) {
    if (!val) this.throwHelp('A: address is required');
    if (!this.isIPv4(val)) this.throwHelp('A address must be IPv4');
    this.set('address', val);
  }

  getDescription() {
    return 'Address'
  }

  getCanonical() {
    return {
      owner: 'host.example.com.',
      class: 'IN',
      ttl: 3600,
      type: 'A',
      address: '192.0.2.127',
    }
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return new Uint8Array(this.get('address').split('.').map(Number))
  }
}

class AAAA extends RR {
  static typeName = 'AAAA'
  static typeId = 28
  static RFCs = [3596, 5952]
  static rdataFields = [['address', 'ipv6']]
  static tags = ['common']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setAddress(val) {
    if (!val) this.throwHelp('AAAA: address is required');
    if (!this.isIPv6(val)) this.throwHelp(`AAAA: address must be IPv6 (${val})`);

    this.set('address', this.expandIPv6(val.toLowerCase())); // lower case: RFC 5952
  }

  getCompressed(val) {
    return this.compressIPv6(val ?? this.get('address'))
  }

  getDescription() {
    return 'Address IPv6'
  }

  getCanonical() {
    return {
      owner: 'host.example.com.',
      address: '2001:0db8:0020:000a:0000:0000:0000:0004',
      class: 'IN',
      ttl: 3600,
      type: 'AAAA',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    const str = tinyline;
    let fqdn, ip, n, rdata, ttl, ts, loc;

    switch (str[0]) {
      case ':':
[fqdn, n, rdata, ttl, ts, loc] = str.slice(1).split(':');
        if (n != 28) this.throwHelp('AAAA fromTinydns, invalid n');
        ip = octalToHex(rdata)
          .match(/([0-9a-fA-F]{4})/g)
          .join(':');
        break
      case '3':
      case '6':
[fqdn, rdata, ttl, ts, loc] = str.slice(1).split(':');
        ip = rdata.match(/(.{4})/g).join(':');
        break
    }

    return new AAAA({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'AAAA',
      address: ip,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    const hex = this.expandIPv6(this.get('address'), '');
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return arr
  }

  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t${this.getCompressed()}\n`
  }

  toTinydns() {
    // from AAAA notation (8 groups of 4 hex digits) to 16 escaped octals
    const rdata = packHex(this.expandIPv6(this.get('address'), ''));
    return this.getTinydnsGeneric(rdata)
  }
}

class APL extends RR {
  static typeName = 'APL'
  static typeId = 42
  static RFCs = [3123]
  static rdataFields = [['apl rdata', 'list']]

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setAplRdata(val) {
    if (!val) this.throwHelp('APL: apl rdata is required');
    this.set('apl rdata', val);
  }

  getDescription() {
    return 'Address Prefix List'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'APL',
      'apl rdata': '1:192.0.2.0/24 !1:192.0.2.64/28 2:2001:db8::1/128',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // APL via generic, :fqdn:42:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':');
    if (n != 42) this.throwHelp('APL fromTinydns, invalid n');

    const bytes = Uint8Array.from(octalToChar(rdata), (c) => c.charCodeAt(0));
    const items = [];
    let pos = 0;

    while (pos < bytes.length) {
      const afi = (bytes[pos] << 8) | bytes[pos + 1];
      pos += 2;
      const prefix = bytes[pos];
      pos++;
      const adfLenByte = bytes[pos];
      pos++;
      const neg = (adfLenByte & 0x80) !== 0;
      const addrLen = adfLenByte & 0x7f;
      const addrBytes = bytes.subarray(pos, pos + addrLen);
      pos += addrLen;

      let addr;
      if (afi === 1) {
        const padded = new Uint8Array(4);
        padded.set(addrBytes);
        addr = [...padded].join('.');
      } else {
        const padded = new Uint8Array(16);
        padded.set(addrBytes);
        const paddedDv = new DataView(padded.buffer);
        const groups = [];
        for (let i = 0; i < 16; i += 2) groups.push(paddedDv.getUint16(i).toString(16).padStart(4, '0'));
        addr = this.compressIPv6(groups.join(':'));
      }

      items.push(`${neg ? '!' : ''}${afi}:${addr}/${prefix}`);
    }

    return new APL({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'APL',
      'apl rdata': items.join(' '),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const items = [];
    let pos = 0;
    while (pos < rdata.length) {
      const afi = (rdata[pos] << 8) | rdata[pos + 1];
      pos += 2;
      const prefix = rdata[pos++];
      const adfLenByte = rdata[pos++];
      const neg = (adfLenByte & 0x80) !== 0;
      const addrLen = adfLenByte & 0x7f;
      const addrBytes = rdata.subarray(pos, pos + addrLen);
      pos += addrLen;

      let addr;
      if (afi === 1) {
        const padded = new Uint8Array(4);
        padded.set(addrBytes);
        addr = [...padded].join('.');
      } else {
        const padded = new Uint8Array(16);
        padded.set(addrBytes);
        const dv = new DataView(padded.buffer);
        const groups = [];
        for (let i = 0; i < 16; i += 2) groups.push(dv.getUint16(i).toString(16).padStart(4, '0'));
        addr = this.compressIPv6(groups.join(':'));
      }
      items.push(`${neg ? '!' : ''}${afi}:${addr}/${prefix}`);
    }
    return new APL({
      owner,
      ttl,
      class: cls,
      type: 'APL',
      'apl rdata': items.join(' '),
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric(
      this.get('apl rdata')
        .split(/\s+/)
        .map((item) => {
          const neg = item.startsWith('!');
          const bare = neg ? item.slice(1) : item;
          const colonIdx = bare.indexOf(':');
          const afi = parseInt(bare.slice(0, colonIdx), 10);
          const rest = bare.slice(colonIdx + 1);
          const slashIdx = rest.lastIndexOf('/');
          const addr = rest.slice(0, slashIdx);
          const prefix = parseInt(rest.slice(slashIdx + 1), 10);

          let addrBytes;
          if (afi === 1) {
            addrBytes = new Uint8Array(addr.split('.').map((n) => parseInt(n, 10)));
          } else {
            const dblIdx = addr.indexOf('::');
            let groups;
            if (dblIdx !== -1) {
              const left = addr
                .slice(0, dblIdx)
                .split(':')
                .filter((s) => s !== '');
              const right = addr
                .slice(dblIdx + 2)
                .split(':')
                .filter((s) => s !== '');
              groups = [...left, ...Array(8 - left.length - right.length).fill('0000'), ...right];
            } else {
              groups = addr.split(':');
            }
            const hexStr = groups.map((g) => g.padStart(4, '0')).join('');
            addrBytes = Uint8Array.from({ length: hexStr.length / 2 }, (_, i) =>
              parseInt(hexStr.slice(i * 2, i * 2 + 2), 16),
            );
          }

          let len = addrBytes.length;
          while (len > 0 && addrBytes[len - 1] === 0) len--;
          const afdPart = addrBytes.slice(0, len);

          let r = UInt16toOctal(afi);
          r += UInt8toOctal(prefix);
          r += UInt8toOctal((neg ? 0x80 : 0) | afdPart.length);
          for (const b of afdPart) r += UInt8toOctal(b);
          return r
        })
        .join(''),
    )
  }

  getWireRdata() {
    const items = this.get('apl rdata').split(/\s+/);
    const rdata = [];

    for (const item of items) {
      const neg = item.startsWith('!');
      const bare = neg ? item.slice(1) : item;
      const colonIdx = bare.indexOf(':');
      const afi = parseInt(bare.slice(0, colonIdx), 10);
      const rest = bare.slice(colonIdx + 1);
      const slashIdx = rest.lastIndexOf('/');
      const addr = rest.slice(0, slashIdx);
      const prefix = parseInt(rest.slice(slashIdx + 1), 10);

      let addrBytes;
      if (afi === 1) {
        addrBytes = new Uint8Array(addr.split('.').map((n) => parseInt(n, 10)));
      } else {
        const dblIdx = addr.indexOf('::');
        let groups;
        if (dblIdx !== -1) {
          const left = addr
            .slice(0, dblIdx)
            .split(':')
            .filter((s) => s !== '');
          const right = addr
            .slice(dblIdx + 2)
            .split(':')
            .filter((s) => s !== '');
          groups = [...left, ...Array(8 - left.length - right.length).fill('0000'), ...right];
        } else {
          groups = addr.split(':');
        }
        const hexStr = groups.map((g) => g.padStart(4, '0')).join('');
        addrBytes = Uint8Array.from({ length: hexStr.length / 2 }, (_, i) =>
          parseInt(hexStr.slice(i * 2, i * 2 + 2), 16),
        );
      }

      let len = addrBytes.length;
      while (len > 0 && addrBytes[len - 1] === 0) len--;
      const afdPart = addrBytes.slice(0, len);

      const itemBytes = new Uint8Array(4 + afdPart.length);
      const dv = new DataView(itemBytes.buffer, itemBytes.byteOffset);
      dv.setUint16(0, afi);
      itemBytes[2] = prefix;
      itemBytes[3] = (neg ? 0x80 : 0) | afdPart.length;
      itemBytes.set(afdPart, 4);

      rdata.push(itemBytes);
    }

    const totalLen = rdata.reduce((sum, r) => sum + r.length, 0);
    const bytes = new Uint8Array(totalLen);
    let pos = 0;
    for (const r of rdata) {
      bytes.set(r, pos);
      pos += r.length;
    }

    return bytes
  }
}

class CAA extends RR {
  static typeName = 'CAA'
  static typeId = 257
  static RFCs = [6844, 8659, 9619]
  static rdataFields = [
    ['flags', 'u8'],
    ['tag', 'charstr'],
    ['value', 'qstr'],
  ]
  static tags = ['security']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setFlags(val) {
    this.is8bitInt('CAA', 'flags', val);

    if (!this.getFlagsOptions().has(val)) {
      this.throwHelp(`CAA flags ${val} not recognized`);
    }

    this.set('flags', val);
  }

  getFlagsOptions() {
    return new Map([
      [0, 'Non Critical'],
      [128, 'Critical'],
    ])
  }

  setTag(val) {
    if (typeof val !== 'string' || val.length < 1 || /[^a-z0-9]/.test(val))
      this.throwHelp(`CAA tag must be a sequence of ASCII letters and numbers in lowercase`);

    if (!this.getTagOptions().has(val)) {
      this.throwHelp(`CAA tag ${val} not recognized`);
    }
    this.set('tag', val);
  }

  getTagOptions() {
    return new Map([['issue'], ['issuewild'], ['iodef']])
  }

  setValue(val) {
    if (this.get('tag') === 'iodef') {
      const iodefSchemes = ['mailto:', 'http:', 'https:'];
      if (!iodefSchemes.filter((s) => val.startsWith(s)).length) {
        this.throwHelp(`CAA value must have valid iodefScheme prefix`);
      }
    }

    this.set('value', val);
  }

  getDescription() {
    return 'Certification Authority Authorization'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'CAA',
      flags: 0,
      tag: 'issue',
      value: 'http://letsencrypt.org',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // CAA via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline);
    if (typeId != this.getTypeId()) this.throwHelp('CAA fromTinydns, invalid typeId');

    const flags = octalToUInt8(rdata.slice(0, 4));
    const taglen = octalToUInt8(rdata.slice(4, 8));

    const unescaped = octalToChar(rdata.slice(8));
    const tag = unescaped.slice(0, taglen);
    const fingerprint = unescaped.slice(taglen);

    return new CAA({
      owner,
      ttl,
      type: 'CAA',
      flags,
      tag,
      value: fingerprint,
      timestamp,
      location,
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const tag = new TextEncoder().encode(this.get('tag'));
    const value = new TextEncoder().encode(this.get('value'));
    const result = new Uint8Array(2 + tag.length + value.length);
    result[0] = this.get('flags');
    result[1] = tag.length;
    result.set(tag, 2);
    result.set(value, 2 + tag.length);
    return result
  }

  toTinydns() {
    return this.getTinydnsGeneric(
      UInt8toOctal(this.get('flags')) +
        UInt8toOctal(this.get('tag').length) +
        escapeOctal(/[\r\n\t:\\/]/, this.get('tag')) +
        escapeOctal(/[\r\n\t:\\/]/, this.get('value')),
    )
  }
}

class CERT extends RR {
  static typeName = 'CERT'
  static typeId = 37
  static RFCs = [2538, 4398]
  static rdataFields = [
    ['cert type', 'certtype'],
    ['key tag', 'u16'],
    ['algorithm', 'u8'],
    ['certificate', 'base64'],
  ]

  static CERT_TYPES = {
    PKIX: 1,
    SPKI: 2,
    PGP: 3,
    IPKIX: 4,
    ISPKI: 5,
    IPGP: 6,
    ACPKIX: 7,
    IACPKIX: 8,
    URI: 253,
    OID: 254,
  }

  static CERT_TYPES_REVERSE = Object.fromEntries(Object.entries(CERT.CERT_TYPES).map(([k, v]) => [v, k]))

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setCertType(val) {
    // The type field is the certificate type
    // the type field as an unsigned decimal integer or as a mnemonic symbol
    if (val === undefined || val === null || val === '') {
      this.throwHelp('cert type is required');
    }
    // Accept both mnemonic and numeric, but validate mnemonic
    if (typeof val === 'string' && !/^[0-9]+$/.test(val)) {
      if (!Object.hasOwn(CERT.CERT_TYPES, val)) {
        this.throwHelp(`CERT: unknown cert type mnemonic: ${val}`);
      }
    } else {
      this.is16bitInt('CERT', 'cert type', val);
    }
    this.set('cert type', val);
  }

  getCertTypeValue(val) {
    if (typeof val === 'number') return val
    if (/^[0-9]+$/.test(val)) return parseInt(val, 10)
    if (Object.hasOwn(CERT.CERT_TYPES, val)) return CERT.CERT_TYPES[val]
    this.throwHelp(`CERT: unknown cert type mnemonic: ${val}`);
  }

  setKeyTag(val) {
    this.setTypedValue('u16', 'key tag', val);
  }

  setAlgorithm(val) {
    this.setTypedValue('u8', 'algorithm', val);
  }

  setCertificate(val) {
    // certificate/CRL portion is represented in base 64 [16] and may be
    // divided into any number of white-space-separated substrings
    if (val === undefined || val === null || val === '') {
      this.throwHelp('certificate is required and cannot be empty');
    }
    this.isBase64('CERT', 'certificate', val.replace(/[\s()]/g, ''));
    this.set('certificate', val);
  }

  getDescription() {
    return 'Certificate'
  }

  getCanonical() {
    return {
      owner: 'mail.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'CERT',
      'cert type': 'PGP',
      'key tag': 0,
      algorithm: 0,
      certificate: 'AQIDBA==',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline);
    if (typeId != this.getTypeId()) this.throwHelp('CERT fromTinydns, invalid n');

    const bytes = octalRdataToBytes(rdata);
    const typeNum = (bytes[0] << 8) | bytes[1];

    const certType = CERT.CERT_TYPES_REVERSE[typeNum] ?? typeNum;

    return new CERT({
      owner,
      ttl,
      type: 'CERT',
      'cert type': certType,
      'key tag': (bytes[2] << 8) | bytes[3],
      algorithm: bytes[4],
      certificate: bytesToBase64(bytes.subarray(5)),
      timestamp,
      location,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    return this.getTinydnsGeneric(
      UInt16toOctal(this.getCertTypeValue(this.get('cert type'))) +
        UInt16toOctal(this.get('key tag')) +
        UInt8toOctal(this.get('algorithm')) +
        base64toOctal(this.get('certificate').replace(/[\s()]/g, '')),
    )
  }

  getWireRdata() {
    const certBytes = base64ToBytes(this.get('certificate').replace(/[\s()]/g, ''));
    const bytes = new Uint8Array(5 + certBytes.length);
    const dv = new DataView(bytes.buffer, bytes.byteOffset);
    dv.setUint16(0, this.getCertTypeValue(this.get('cert type')));
    dv.setUint16(2, this.get('key tag'));
    bytes[4] = this.get('algorithm');
    bytes.set(certBytes, 5);
    return bytes
  }
}

class CNAME extends RR {
  static typeName = 'CNAME'
  static typeId = 5
  static RFCs = [1035, 2181]
  static tinydnsType = 'C'
  static rdataFields = [['cname', 'fqdn']]
  static tags = ['common']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setCname(val) {
    this.setTypedValue('fqdn', 'cname', val);
  }

  getDescription() {
    return 'Canonical Name'
  }

  getCanonical() {
    return {
      owner: 'www.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'CNAME',
      cname: 'web.example.com.',
    }
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return this.wirePackDomain(this.get('cname'))
  }
}

class DHCID extends RR {
  static typeName = 'DHCID'
  static typeId = 49
  static RFCs = [4701]
  static rdataFields = [['data', 'base64']]

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setData(val) {
    if (!val) this.throwHelp('DHCID: data is required');
    this.isBase64('DHCID', 'data', val);
    this.set('data', val);
  }

  getDescription() {
    return 'DHCP Identifier'
  }

  getCanonical() {
    return {
      owner: 'host.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'DHCID',
      data: 'AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // DHCID via generic, :fqdn:49:rdata:ttl:timestamp:lo
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline);
    if (typeId != this.getTypeId()) this.throwHelp('DHCID fromTinydns, invalid n');

    return new DHCID({
      owner,
      ttl,
      type: 'DHCID',
      data: octalToBase64(rdata),
      timestamp,
      location,
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    return new Uint8Array(
      atob(this.get('data'))
        .split('')
        .map((c) => c.charCodeAt(0)),
    )
  }

  toTinydns() {
    return this.getTinydnsGeneric(base64toOctal(this.get('data')))
  }
}

class DNAME extends RR {
  static typeName = 'DNAME'
  static typeId = 39
  static RFCs = [2672, 6672]
  static rdataFields = [['target', 'fqdn']]

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setTarget(val) {
    this.setTypedValue('fqdn', 'target', val);
  }

  getDescription() {
    return 'Delegation Name'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'DNAME',
      target: 'example.net.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // DNAME via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':');
    if (n != 39) this.throwHelp('DNAME fromTinydns, invalid n');

    return new DNAME({
      type: 'DNAME',
      owner: this.fullyQualify(fqdn),
      target: unpackDomainName(rdata)[0],
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    return this.wirePackDomain(this.get('target'))
  }

  toTinydns() {
    const rdata = packDomainName(this.get('target'));
    return this.getTinydnsGeneric(rdata)
  }
}

class DNSKEY extends RR {
  static typeName = 'DNSKEY'
  static typeId = 48
  static RFCs = [4034, 6014, 8624, 9619, 9905]
  static rdataFields = [
    ['flags', 'u16'],
    ['protocol', 'u8'],
    ['algorithm', 'u8'],
    ['publickey', 'base64'],
  ]
  static tags = ['dnssec']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setFlags(val) {
    // a 2 octet Flags Field
    this.is16bitInt('DNSKEY', 'flags', val);

    if (!this.getFlagsOptions().has(val)) {
      this.throwHelp(`DNSKEY: flags must be in the set: ${this.getFlagsOptions()}`);
    }

    this.set('flags', val);
  }

  // possible values are: 0, 256, and 257; RFC 4034
  getFlagsOptions() {
    return new Map([[0], [256], [257]])
  }

  setProtocol(val) {
    // 1 octet
    this.is8bitInt('DNSKEY', 'protocol', val);

    // The Protocol Field MUST be represented as an unsigned decimal integer with a value of 3.
    if (!this.getProtocolOptions().has(val)) this.throwHelp(`DNSKEY: protocol invalid`);

    this.set('protocol', val);
  }

  getProtocolOptions() {
    return new Map([[3]])
  }

  setAlgorithm(val) {
    // 1 octet
    this.is8bitInt('DNSKEY', 'algorithm', val);

    // https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    if (!this.getAlgorithmOptions().has(val)) console.error(`DNSKEY: algorithm (${val}) not recognized`);

    this.set('algorithm', val);
  }

  getAlgorithmOptions() {
    return new Map([
      [1, 'RSA/MD5 (DEPRECATED)'],
      [2, 'DH'],
      [3, 'DSA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [6, 'DSA-NSEC3-SHA1'],
      [7, 'RSASHA1-NSEC3-SHA1'],
      [8, 'RSA/SHA-256'],
      [9, ''],
      [10, 'RSA/SHA-512'],
      [13, 'ECDSA Curve P-256 with SHA-256'],
      [14, 'ECDSA Curve P-384 with SHA-384'],
      [15, 'Ed25519'],
      [16, 'Ed448'],
      [253],
      [254],
    ])
  }

  setPublickey(val) {
    if (!val) this.throwHelp(`DNSKEY: publickey is required`);
    this.isBase64('DNSKEY', 'publickey', val.replace(/[\s()]/g, ''));
    this.set('publickey', val);
  }

  getDescription() {
    return 'DNS Public Key'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'DNSKEY',
      flags: 256,
      protocol: 3,
      algorithm: 5,
      publickey:
        'AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwIXAqcOTiW7iHnQt5hwVAAAAA==',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline);
    if (typeId != this.getTypeId()) this.throwHelp('DNSKEY fromTinydns, invalid n');

    const bytes = octalRdataToBytes(rdata);

    return new DNSKEY({
      owner,
      ttl,
      type: 'DNSKEY',
      flags: (bytes[0] << 8) | bytes[1],
      protocol: bytes[2],
      algorithm: bytes[3],
      publickey: bytesToBase64(bytes.subarray(4)),
      timestamp,
      location,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    return this.getTinydnsGeneric(
      UInt16toOctal(this.get('flags')) +
        UInt8toOctal(this.get('protocol')) +
        UInt8toOctal(this.get('algorithm')) +
        base64toOctal(this.get('publickey').replace(/[\s()]/g, '')),
    )
  }

  getWireRdata() {
    const keyBytes = base64ToBytes(this.get('publickey').replace(/[\s()]/g, ''));
    const bytes = new Uint8Array(4 + keyBytes.length);
    const dv = new DataView(bytes.buffer, bytes.byteOffset);
    dv.setUint16(0, this.get('flags'));
    bytes[2] = this.get('protocol');
    bytes[3] = this.get('algorithm');
    bytes.set(keyBytes, 4);
    return bytes
  }
}

// RFC 4034 §5.1.4, RFC 4509, RFC 6605: SHA-1, SHA-256 and SHA-384 digests.
const DIGEST_BYTES$2 = { 1: 20, 2: 32, 4: 48 };

class DS extends RR {
  static typeName = 'DS'
  static typeId = 43
  static RFCs = [4034, 4509, 9619]
  static rdataFields = [
    ['key tag', 'u16'],
    ['algorithm', 'u8'],
    ['digest type', 'u8'],
    ['digest', 'str'],
  ]
  static tags = ['dnssec']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setKeyTag(val) {
    this.setTypedValue('u16', 'key tag', val);
  }

  setDigest(val) {
    this.isHexDigest('digest', val, DIGEST_BYTES$2[this.get('digest type')]);
    this.set('digest', val);
  }

  setAlgorithm(val) {
    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`DS: algorithm invalid`);

    this.set('algorithm', val);
  }

  getAlgorithmOptions() {
    // IANA DNSSEC Algorithm Numbers
    // https://www.iana.org/assignments/dns-sec-alg-numbers/
    return new Map([
      [1, 'RSA/MD5'],
      [2, 'DH'],
      [3, 'DSA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [6, 'DSA-NSEC3-SHA1'],
      [7, 'RSASHA1-NSEC3-SHA1'],
      [8, 'RSA/SHA-256'],
      [10, 'RSA/SHA-512'],
      [13, 'ECDSA P-256/SHA-256'],
      [14, 'ECDSA P-384/SHA-384'],
      [15, 'Ed25519'],
      [16, 'Ed448'],
      [253, ''],
      [254, ''],
    ])
  }

  setDigestType(val) {
    if (!Object.hasOwn(DIGEST_BYTES$2, val)) this.throwHelp(`DS: digest type invalid`);
    if (this.get('digest') !== undefined) this.isHexDigest('digest', this.get('digest'), DIGEST_BYTES$2[val]);
    this.set('digest type', val);
  }

  getDescription() {
    return 'Delegation Signer'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'DS',
      'key tag': 60485,
      algorithm: 5,
      'digest type': 1,
      digest: '2BB183AF5F22588179A53B0A98631FAD1A292118',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns(opts) {
    const { tinyline } = opts;
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline);
    if (typeId != this.getTypeId()) this.throwHelp('DS fromTinydns, invalid n');

    const binRdata = octalRdataToBytes(rdata);

    return new DS({
      owner,
      ttl,
      type: 'DS',
      'key tag': (binRdata[0] << 8) | binRdata[1],
      algorithm: binRdata[2],
      'digest type': binRdata[3],
      digest: bytesToHex(binRdata.subarray(4)).toUpperCase(),
      timestamp,
      location,
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const dv = new DataView(rdata.buffer, rdata.byteOffset);
    return new DS({
      owner,
      ttl,
      class: cls,
      type: 'DS',
      'key tag': dv.getUint16(0),
      algorithm: rdata[2],
      'digest type': rdata[3],
      digest: bytesToHex(rdata.subarray(4)).toUpperCase(),
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    return this.getTinydnsGeneric(
      UInt16toOctal(this.get('key tag')) +
        UInt8toOctal(this.get('algorithm')) +
        UInt8toOctal(this.get('digest type')) +
        packHex(this.get('digest').replace(/\s+/g, '')),
    )
  }

  getWireRdata() {
    const digestBytes = hexToBytes(this.get('digest').replace(/\s+/g, ''));
    const bytes = new Uint8Array(4 + digestBytes.length);
    const dv = new DataView(bytes.buffer, bytes.byteOffset);
    dv.setUint16(0, this.get('key tag'));
    bytes[2] = this.get('algorithm');
    bytes[3] = this.get('digest type');
    bytes.set(digestBytes, 4);
    return bytes
  }
}

class HINFO extends RR {
  static typeName = 'HINFO'
  static typeId = 13
  static RFCs = [1034, 1035, 8482]
  static rdataFields = [
    ['cpu', 'qcharstr'],
    ['os', 'qcharstr'],
  ]
  static tags = ['obsolete']

  constructor(opts) {
    super(opts);
  }

  getDescription() {
    return 'Host Info'
  }

  getCanonical() {
    return {
      owner: 'test.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'HINFO',
      cpu: 'DEC-2060',
      os: 'TOPS20',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // HINFO via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, , rdata, ttl, ts, loc] = tinyline.slice(1).split(':');
    const [cpu, os] = [...unpackString(rdata)];

    return new this.constructor({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'HINFO',
      cpu,
      os,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const cpu = new TextEncoder().encode(this.get('cpu'));
    const os = new TextEncoder().encode(this.get('os'));
    const result = new Uint8Array(2 + cpu.length + os.length);
    result[0] = cpu.length;
    result.set(cpu, 1);
    result[1 + cpu.length] = os.length;
    result.set(os, 2 + cpu.length);
    return result
  }

  toTinydns() {
    return this.getTinydnsGeneric(
      [packString(this.get('cpu')), packString(this.get('os'))].join(''),
    )
  }
}

class HIP extends RR {
  static typeName = 'HIP'
  static typeId = 55
  static RFCs = [8005]
  static rdataFields = [['pk algorithm', 'u8'], 'hit', 'public key', ['rendezvous servers', 'list']]

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setPkAlgorithm(val) {
    if (val === undefined) this.throwHelp('HIP: pk algorithm is required');
    this.is8bitInt('HIP', 'pk algorithm', val);
    this.set('pk algorithm', val);
  }

  setHit(val) {
    if (!val) this.throwHelp('HIP: hit is required');
    this.set('hit', val);
  }

  setPublicKey(val) {
    if (!val) this.throwHelp('HIP: public key is required');
    this.set('public key', val);
  }

  setRendezvousServers(val) {
    for (const name of (val ?? '').split(/\s+/).filter(Boolean)) {
      this.isFullyQualified('HIP', 'rendezvous servers', name);
      this.hasValidLabels(name);
    }
    this.set('rendezvous servers', val ?? '');
  }

  getDescription() {
    return 'Host Identity Protocol'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'HIP',
      'pk algorithm': 2,
      hit: '200100107B1A74DF365639CC39F1D578',
      'public key':
        'AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwIXAqcOTiW7iHnQt5hwVAAAAA==',
      'rendezvous servers': '',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // HIP via generic, :fqdn:55:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':');
    if (n != 55) this.throwHelp('HIP fromTinydns, invalid n');

    const bytes = Uint8Array.from(octalToChar(rdata), (c) => c.charCodeAt(0));
    const hitLen = bytes[0];
    const pkAlgorithm = bytes[1];
    const pkLen = (bytes[2] << 8) | bytes[3];

    const hit = bytesToHex(bytes.subarray(4, 4 + hitLen)).toUpperCase();
    const publicKey = bytesToBase64(bytes.subarray(4 + hitLen, 4 + hitLen + pkLen));

    const rvsNames = [];
    let pos = 4 + hitLen + pkLen;
    while (pos < bytes.length) {
      const [name, newPos] = unpackDomainName(
        [...bytes.subarray(pos)]
          .map((b) => (b < 32 || b > 126 ? UInt8toOctal(b) : String.fromCharCode(b)))
          .join(''),
      );
      pos += newPos;
      if (name !== '.') rvsNames.push(name);
    }

    return new HIP({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'HIP',
      'pk algorithm': pkAlgorithm,
      hit,
      'public key': publicKey,
      'rendezvous servers': rvsNames.join(' '),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const dv = new DataView(rdata.buffer, rdata.byteOffset);
    const hitLen = rdata[0];
    const pkAlgorithm = rdata[1];
    const pkLen = dv.getUint16(2);
    const hit = bytesToHex(rdata.subarray(4, 4 + hitLen)).toUpperCase();
    const publicKey = bytesToBase64(rdata.subarray(4 + hitLen, 4 + hitLen + pkLen));
    const rvsNames = [];
    let pos = 4 + hitLen + pkLen;
    while (pos < rdata.length) {
      const { fqdn, end } = this.wireUnpackDomain(rdata, pos);
      rvsNames.push(fqdn);
      pos = end;
    }
    return new HIP({
      owner,
      ttl,
      class: cls,
      type: 'HIP',
      'pk algorithm': pkAlgorithm,
      hit,
      'public key': publicKey,
      'rendezvous servers': rvsNames.join(' '),
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    const rs = this.get('rendezvous servers');
    const rsPart = rs ? `\t${rs}` : '';
    return `${this.getPrefix(zone_opts)}\t${this.get('pk algorithm')}\t${this.get('hit')}\t${this.get('public key')}${rsPart}\n`
  }

  toTinydns() {
    const hitHex = this.get('hit');
    const hitBytes = hexToBytes(hitHex);
    const pkBytes = base64ToBytes(this.get('public key'));
    const rs = this.get('rendezvous servers');

    let rdata = '';
    rdata += UInt8toOctal(hitBytes.length);
    rdata += UInt8toOctal(this.get('pk algorithm'));
    rdata += UInt16toOctal(pkBytes.length);
    for (const b of hitBytes) rdata += UInt8toOctal(b);
    for (const b of pkBytes) rdata += UInt8toOctal(b);
    if (rs) {
      for (const name of rs.split(/\s+/)) rdata += packDomainName(name);
    }

    return this.getTinydnsGeneric(rdata)
  }

  getWireRdata() {
    const hitHex = this.get('hit');
    const hitBytes = hexToBytes(hitHex);
    const pkBytes = base64ToBytes(this.get('public key'));
    const rs = this.get('rendezvous servers');

    const rsNames = rs ? rs.split(/\s+/) : [];
    const rsDomains = rsNames.map((name) => wirePackDomain(name));
    const rsTotalLen = rsDomains.reduce((sum, b) => sum + b.length, 0);

    const totalLen = 1 + 1 + 2 + hitBytes.length + pkBytes.length + rsTotalLen;
    const bytes = new Uint8Array(totalLen);
    const dv = new DataView(bytes.buffer, bytes.byteOffset);

    let pos = 0;
    bytes[pos++] = hitBytes.length;
    bytes[pos++] = this.get('pk algorithm');
    dv.setUint16(pos, pkBytes.length);
    pos += 2;
    bytes.set(hitBytes, pos);
    pos += hitBytes.length;
    bytes.set(pkBytes, pos);
    pos += pkBytes.length;
    for (const rdomain of rsDomains) {
      bytes.set(rdomain, pos);
      pos += rdomain.length;
    }

    return bytes
  }
}

class HTTPS extends RR {
  static typeName = 'HTTPS'
  static typeId = 65
  static RFCs = [9460]
  static tags = ['common']
  static rdataFields = [
    ['priority', 'u16'],
    ['target name', 'fqdn'],
    ['params', 'svcparams'],
  ]

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.is16bitInt('HTTPS', 'priority', val);

    this.set('priority', val);
  }

  setTargetName(val) {
    if (!val) this.throwHelp('HTTPS: target name is required');
    this.isFullyQualified('HTTPS', 'target name', val);
    this.isValidName('HTTPS', 'target name', val);

    // RFC 4034: letters in the DNS names are lower cased
    this.set('target name', this.lowercaseName(val));
  }

  setParams(val) {
    this.setTypedValue('svcparams', 'params', val);
  }

  getDescription() {
    return 'HTTP Semantics'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'HTTPS',
      priority: 1,
      'target name': 'example.com.',
      params: 'alpn="h2,h3"',
    }
  }

  /******  IMPORTERS   *******/

  /******  EXPORTERS   *******/

  getWireRdata() {
    const targetBytes = this.wirePackDomain(this.get('target name'));
    const paramsBytes = svcParamsToWire(this.get('params'));
    const result = new Uint8Array(2 + targetBytes.length + paramsBytes.length);
    new DataView(result.buffer).setUint16(0, this.get('priority'));
    result.set(targetBytes, 2);
    result.set(paramsBytes, 2 + targetBytes.length);
    return result
  }
}

class IPSECKEY extends RR {
  static typeName = 'IPSECKEY'
  static typeId = 45
  static RFCs = [4025]
  static rdataFields = [
    ['precedence', 'u8'],
    ['gateway type', 'u8'],
    ['algorithm', 'u8'],
    'gateway',
    ['publickey', 'base64'],
  ]
  static tags = ['security']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setPrecedence(val) {
    // an 8-bit precedence for this record.
    this.is8bitInt('IPSECKEY', 'precedence', val);

    this.set('precedence', val);
  }

  setGatewayType(val) {
    if (!this.getGatewayTypeOptions().has(val)) this.throwHelp(`IPSECKEY: Gateway Type is invalid`);

    this.set('gateway type', val);
  }

  getGatewayTypeOptions() {
    return new Map([
      [0, 'none'],
      [1, '4-byte IPv4'],
      [2, '16-byte IPv6'],
      [3, 'wire encoded domain name'],
    ])
  }

  setAlgorithm(val) {
    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`IPSECKEY: Algorithm invalid`);

    this.set('algorithm', val);
  }

  getAlgorithmOptions() {
    return new Map([
      [1, 'DSA'],
      [2, 'RSA'],
    ])
  }

  setGateway(val) {
    const type = this.get('gateway type');
    const gwErr = new Error(`IPSECKEY: gateway invalid (${val}) for type ${type}`);
    switch (type) {
      case 0:
        if (val !== '.') throw gwErr
        break
      case 1:
        if (!this.isIPv4(val)) throw gwErr
        break
      case 2:
        if (!this.isIPv6(val)) throw gwErr
        val = this.expandIPv6(val.toLowerCase());
        break
    }

    this.set('gateway', val);
  }

  setPublickey(val) {
    if (val) this.isBase64('IPSECKEY', 'publickey', val);
    this.set('publickey', val);
  }

  getDescription() {
    return 'IPsec Keying'
  }

  getCanonical() {
    return {
      owner: '38.2.0.192.in-addr.arpa.',
      ttl: 7200,
      class: 'IN',
      type: 'IPSECKEY',
      precedence: 10,
      'gateway type': 1,
      algorithm: 2,
      gateway: '192.0.2.38',
      publickey: 'AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
    }
  }

  /******  IMPORTERS   *******/

  fromWire({ owner, cls, ttl, rdata }) {
    const precedence = rdata[0];
    const gwType = rdata[1];
    const algorithm = rdata[2];
    let gateway, keyStart;
    switch (gwType) {
      case 0:
        gateway = '.';
        keyStart = 3;
        break
      case 1:
        gateway = [...rdata.subarray(3, 7)].join('.');
        keyStart = 7;
        break
      case 2: {
        const dv = new DataView(rdata.buffer, rdata.byteOffset + 3);
        const groups = [];
        for (let i = 0; i < 16; i += 2) groups.push(dv.getUint16(i).toString(16).padStart(4, '0'));
        gateway = groups.join(':');
        keyStart = 19;
        break
      }
      case 3: {
        const { fqdn, end } = this.wireUnpackDomain(rdata, 3);
        gateway = fqdn;
        keyStart = end;
        break
      }
    }
    const publickey = bytesToBase64(rdata.subarray(keyStart));
    return new IPSECKEY({
      owner,
      ttl,
      class: cls,
      type: 'IPSECKEY',
      precedence,
      'gateway type': gwType,
      algorithm,
      gateway,
      publickey,
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const pubkeyBytes = base64ToBytes(this.get('publickey'));
    const gwType = this.get('gateway type');

    let gwBytes;
    switch (gwType) {
      case 0:
        gwBytes = new Uint8Array(0);
        break
      case 1:
        gwBytes = new Uint8Array(4);
        this.get('gateway')
          .split('.')
          .forEach((part, i) => {
            gwBytes[i] = parseInt(part, 10);
          });
        break
      case 2:
        gwBytes = new Uint8Array(16);
        {
          const parts = this.get('gateway').split(':');
          let pos = 0;
          for (const part of parts) {
            if (part === '') continue
            const val = parseInt(part, 16);
            gwBytes[pos++] = (val >>> 8) & 0xff;
            gwBytes[pos++] = val & 0xff;
          }
        }
        break
      case 3:
        gwBytes = wirePackDomain(this.get('gateway'));
        break
    }

    const bytes = new Uint8Array(3 + gwBytes.length + pubkeyBytes.length);
    bytes[0] = this.get('precedence');
    bytes[1] = gwType;
    bytes[2] = this.get('algorithm');
    bytes.set(gwBytes, 3);
    bytes.set(pubkeyBytes, 3 + gwBytes.length);

    return bytes
  }
}

class KEY extends RR {
  static typeName = 'KEY'
  static typeId = 25
  static RFCs = [2535, 3445, 4034, 6840]
  static rdataFields = [
    ['flags', 'u16'],
    ['protocol', 'u8'],
    ['algorithm', 'u8'],
    ['publickey', 'base64'],
  ]
  static tags = ['obsolete']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setFlags(val) {
    // a 2 octet Flags Field
    this.is16bitInt('KEY', 'flags', val);

    this.set('flags', val);
  }

  setProtocol(val) {
    // 1 octet
    this.is8bitInt('KEY', 'protocol', val);

    this.set('protocol', val);
  }

  setAlgorithm(val) {
    // 1 octet

    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`KEY: algorithm invalid`);

    this.set('algorithm', val);
  }

  getAlgorithmOptions() {
    return new Map([
      [1, 'RSA/MD5'],
      [2, 'DH'],
      [3, 'DSA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [253, ''],
      [254, ''],
    ])
  }

  setPublickey(val) {
    if (!val) this.throwHelp(`KEY: publickey is required`);
    this.isBase64('KEY', 'publickey', val.replace(/[\s()]/g, ''));
    this.set('publickey', val);
  }

  getDescription() {
    return 'DNS Public Key'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'KEY',
      flags: 256,
      protocol: 3,
      algorithm: 5,
      publickey:
        'AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwIXAqcOTiW7iHnQt5hwVAAAAA==',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    // RDATA format: Flags (8 octal chars) + Protocol (4 octal chars) + Algorithm (4 octal chars) + Public Key (escaped data)
    const { owner, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline);
    if (rdata.length < 16) {
      this.throwHelp(`KEY: RDATA too short: ${rdata}`);
    }

    return new KEY({
      owner,
      ttl,
      type: 'KEY',
      flags: octalToUInt16(rdata.slice(0, 8)),
      protocol: octalToUInt8(rdata.slice(8, 12)),
      algorithm: octalToUInt8(rdata.slice(12, 16)),
      publickey: octalToBase64(rdata.slice(16)),
      timestamp,
      location,
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric(
      UInt16toOctal(this.get('flags')) +
        UInt8toOctal(this.get('protocol')) +
        UInt8toOctal(this.get('algorithm')) +
        base64toOctal(this.get('publickey').replace(/[\s()]/g, '')),
    )
  }

  getWireRdata() {
    const keyBytes = base64ToBytes(this.get('publickey').replace(/[\s()]/g, ''));
    const bytes = new Uint8Array(4 + keyBytes.length);
    const dv = new DataView(bytes.buffer, bytes.byteOffset);
    dv.setUint16(0, this.get('flags'));
    bytes[2] = this.get('protocol');
    bytes[3] = this.get('algorithm');
    bytes.set(keyBytes, 4);
    return bytes
  }
}

class KX extends RR {
  static typeName = 'KX'
  static typeId = 36
  static RFCs = [2230]
  static rdataFields = [
    ['preference', 'u16'],
    ['exchanger', 'fqdn'],
  ]

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setPreference(val) {
    if (val === undefined) this.throwHelp('KX: preference is required');
    this.is16bitInt('KX', 'preference', val);
    this.set('preference', val);
  }

  setExchanger(val) {
    if (!val) this.throwHelp('KX: exchanger is required');

    this.isFullyQualified('KX', 'exchanger', val);
    this.isValidName('KX', 'exchanger', val);

    this.set('exchanger', this.lowercaseName(val));
  }

  getDescription() {
    return 'Key Exchanger'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'KX',
      preference: 10,
      exchanger: 'kx.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // KX via generic, :fqdn:36:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':');
    if (n != 36) this.throwHelp('KX fromTinydns, invalid n');

    return new KX({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'KX',
      preference: octalToUInt16(rdata.slice(0, 8)),
      exchanger: unpackDomainName(rdata.slice(8))[0],
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const exchanger = this.wirePackDomain(this.get('exchanger'));
    const result = new Uint8Array(2 + exchanger.length);
    const dv = new DataView(result.buffer);
    dv.setUint16(0, this.get('preference'));
    result.set(exchanger, 2);
    return result
  }

  toTinydns() {
    return this.getTinydnsGeneric(
      UInt16toOctal(this.get('preference')) + packDomainName(this.get('exchanger')),
    )
  }
}

const REF = {
  // RFC 1876
  LATLON: 2 ** 31, // LAT equator, LON prime meridian
  ALTITUDE: 100000 * 100, // reference spheroid used by GPS, in cm
};

const CONV = {
  sec: 1000,
  min: 60 * 1000,
  deg: 60 * 60 * 1000,
};

class LOC extends RR {
  static typeName = 'LOC'
  static typeId = 29
  static RFCs = [1876]
  static rdataFields = [['address', 'list']]

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setAddress(val) {
    if (!val) this.throwHelp('LOC: address is required');

    /*
    ... LOC ( d1 [m1 [s1]] {"N"|"S"} d2 [m2 [s2]]
             {"E"|"W"} alt["m"] [siz["m"] [hp["m"]
             [vp["m"]]]] )
    */
    this.parseLoc(val);

    this.set('address', val);
  }

  getDescription() {
    return 'Location'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'LOC',
      address: '52 22 23.000 N 4 53 32.000 E 10m 100m 10m 2m',
    }
  }

  parseLoc(string) {
    // d1 [m1 [s1]]
    const dms = '(\\d+)\\s+(?:(\\d+)\\s+)?(?:([\\d.]+)\\s+)?';

    // alt["m"] [siz["m"] [hp["m"] [vp["m"]]]]
    const alt = '(-?[\\d.]+)m?(?:\\s+([\\d.]+)m?)?(?:\\s+([\\d.]+)m?)?(?:\\s+([\\d.]+)m?)?';

    // put them all together
    const locRe = new RegExp(`^${dms}(N|S)\\s+${dms}(E|W)\\s+${alt}`, 'i');
    const r = string.match(locRe);
    if (!r) this.throwHelp('LOC address: invalid format, see RFC 1876');

    const loc = {
      latitude: {
        degrees: r[1],
        minutes: r[2],
        seconds: r[3],
        hemisphere: r[4].toUpperCase(),
      },
      longitude: {
        degrees: r[5],
        minutes: r[6],
        seconds: r[7],
        hemisphere: r[8].toUpperCase(),
      },
      altitude: r[9] * 100, // m -> cm
      size: (r[10] ?? DEFAULT_CM[0] / 100) * 100,
      precision: {
        horizontal: (r[11] ?? DEFAULT_CM[1] / 100) * 100,
        vertical: (r[12] ?? DEFAULT_CM[2] / 100) * 100,
      },
    };

    return loc
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // LOC via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':');
    if (n != 29) this.throwHelp('LOC fromTinydns, invalid n');

    // divide by 100 is to convert cm to meters
    const l = {
      version: octalToUInt8(rdata.slice(0, 4)),
      size: this.fromExponent(octalToUInt8(rdata.slice(4, 8))),
      precision: {
        horizontal: this.fromExponent(octalToUInt8(rdata.slice(8, 12))),
        vertical: this.fromExponent(octalToUInt8(rdata.slice(12, 16))),
      },
      latitude: this.arcSecToDMS(octalToUInt32(rdata.slice(16, 32)), 'lat'),
      longitude: this.arcSecToDMS(octalToUInt32(rdata.slice(32, 48)), 'lon'),
      altitude: octalToUInt32(rdata.slice(48, 64)) - REF.ALTITUDE,
    };

    return new LOC({
      type: 'LOC',
      owner: this.fullyQualify(fqdn),
      address: this.toHuman(l),
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  dmsToArcSec(obj) {
    let retval = obj.degrees * CONV.deg + (obj.minutes ?? 0) * CONV.min + (obj.seconds ?? 0) * CONV.sec;
    switch (obj.hemisphere.toUpperCase()) {
      case 'W':
      case 'S':
        retval = -retval;
        break
    }
    retval += REF.LATLON;
    return retval
  }

  arcSecToDMS(rawmsec, latlon) {
    let msec = Math.abs(rawmsec - REF.LATLON);
    // console.log(`rawmsec: ${rawmsec}, abs msec: ${msec}`)

    const deg = Math.floor(msec / CONV.deg);
    msec -= deg * CONV.deg;

    const min = Math.floor(msec / CONV.min);
    msec -= min * CONV.min;

    const sec = Math.floor(msec / CONV.sec);
    msec -= sec * CONV.sec;

    let hem;
    switch (latlon) {
      case 'lat':
        hem = rawmsec >= REF.LATLON ? 'N' : 'S';
        break
      case 'lon':
        hem = rawmsec >= REF.LATLON ? 'E' : 'W';
        break
      default:
        this.throwHelp('unknown or missing hemisphere');
    }

    return `${deg} ${min} ${sec}${msec ? '.' + msec : ''} ${hem}`
  }

  fromExponent(prec) {
    const mantissa = ((prec >> 4) & 0x0f) % 10;
    const exponent = ((prec >> 0) & 0x0f) % 10;
    return mantissa * Math.pow(10, exponent)
  }

  toExponent(val) {
    /*
     RFC 1876, ... expressed as a pair of four-bit unsigned
     integers, each ranging from zero to nine, with the most
     significant four bits representing the base and the second
     number representing the power of ten by which to multiply
     the base.
    */
    let exponent = 0;
    while (val >= 10) {
      val /= 10;
      ++exponent;
    }
    return (parseInt(val) << 4) | (exponent & 0x0f)
  }

  toHuman(obj) {
    const optional = [obj.size, obj.precision.horizontal, obj.precision.vertical];
    while (optional.length && optional.at(-1) === DEFAULT_CM[optional.length - 1]) optional.pop();
    return [
      `${obj.latitude} ${obj.longitude} ${obj.altitude / 100}m`,
      ...optional.map((cm) => `${cm / 100}m`),
    ].join(' ')
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const dv = new DataView(rdata.buffer, rdata.byteOffset);
    const l = {
      size: this.fromExponent(rdata[1]),
      precision: {
        horizontal: this.fromExponent(rdata[2]),
        vertical: this.fromExponent(rdata[3]),
      },
      latitude: this.arcSecToDMS(dv.getUint32(4), 'lat'),
      longitude: this.arcSecToDMS(dv.getUint32(8), 'lon'),
      altitude: dv.getUint32(12) - REF.ALTITUDE,
    };
    return new LOC({
      owner,
      ttl,
      class: cls,
      type: 'LOC',
      address: this.toHuman(l),
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const loc = this.parseLoc(this.get('address'));

    // LOC format declares in meters, tinydns uses cm (hence * 100)
    let rdata = '';
    rdata += UInt8toOctal(0); // version
    rdata += UInt8toOctal(this.toExponent(loc.size));
    rdata += UInt8toOctal(this.toExponent(loc.precision.horizontal));
    rdata += UInt8toOctal(this.toExponent(loc.precision.vertical));
    rdata += UInt32toOctal(this.dmsToArcSec(loc.latitude));
    rdata += UInt32toOctal(this.dmsToArcSec(loc.longitude));
    rdata += UInt32toOctal(loc.altitude + REF.ALTITUDE);

    return this.getTinydnsGeneric(rdata)
  }

  getWireRdata() {
    const loc = this.parseLoc(this.get('address'));
    const bytes = new Uint8Array(16);
    const dv = new DataView(bytes.buffer, bytes.byteOffset);

    bytes[0] = 0; // version
    bytes[1] = this.toExponent(loc.size);
    bytes[2] = this.toExponent(loc.precision.horizontal);
    bytes[3] = this.toExponent(loc.precision.vertical);
    dv.setUint32(4, this.dmsToArcSec(loc.latitude));
    dv.setUint32(8, this.dmsToArcSec(loc.longitude));
    dv.setUint32(12, loc.altitude + REF.ALTITUDE);

    return bytes
  }
}

// RFC 1876 §2: omitted size, horizontal and vertical precision are 1m, 10000m and 10m.
const DEFAULT_CM = [100, 1000000, 1000];

class MX extends RR {
  static typeName = 'MX'
  static typeId = 15
  static RFCs = [1035, 2181, 7505]
  static tinydnsType = '@'
  static rdataFields = [
    ['preference', 'u16'],
    ['exchange', 'fqdn'],
  ]
  static tags = ['common']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setPreference(val) {
    if (val === undefined) val = this?.default?.preference;
    if (val === undefined) this.throwHelp('MX: preference is required');
    this.is16bitInt('MX', 'preference', val);
    this.set('preference', val);
  }

  setExchange(val) {
    this.setTypedValue('fqdn', 'exchange', val);
  }

  getDescription() {
    return 'Mail Exchanger'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 43200,
      class: 'IN',
      type: 'MX',
      preference: 10,
      exchange: 'mail.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // @fqdn:ip:x:dist:ttl:timestamp:lo
    const [owner, _ip, x, preference, ttl, ts, loc] = tinyline.slice(1).split(':');

    return new MX({
      type: 'MX',
      owner: this.fullyQualify(owner),
      exchange: this.fullyQualify(/\./.test(x) ? x : `${x}.mx.${owner}`),
      preference: parseInt(preference, 10) || 0,
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    const domain = this.wirePackDomain(this.get('exchange'));
    const result = new Uint8Array(2 + domain.length);
    new DataView(result.buffer).setUint16(0, this.get('preference'));
    result.set(domain, 2);
    return result
  }

  toTinydns() {
    return `@${this.getTinyFQDN('owner')}::${this.getTinyFQDN('exchange')}:${this.get('preference')}:${this.getTinydnsPostamble()}\n`
  }
}

class NAPTR extends RR {
  static typeName = 'NAPTR'
  static typeId = 35
  static RFCs = [2915, 3403, 4848]
  static rdataFields = [
    ['order', 'u16'],
    ['preference', 'u16'],
    ['flags', 'qcharstr'],
    ['service', 'qcharstr'],
    ['regexp', 'qcharstr'],
    ['replacement', 'fqdn'],
  ]

  constructor(opts) {
    super(opts);
  }

  getDescription() {
    return 'Naming Authority Pointer'
  }

  getCanonical() {
    return {
      owner: 'cid.urn.arpa.',
      ttl: 3600,
      class: 'IN',
      type: 'NAPTR',
      order: 100,
      preference: 10,
      flags: 'S',
      service: 'z3950+N2L+N2R',
      regexp: '',
      replacement: 'gatekeeper.example.com.',
    }
  }

  /****** Resource record specific setters   *******/
  setOrder(val) {
    this.is16bitInt('NAPTR', 'order', val);
    this.set('order', val);
  }

  setPreference(val) {
    this.is16bitInt('NAPTR', 'preference', val);
    this.set('preference', val);
  }

  setFlags(val) {
    if (!this.getFlagsOptions().has(val.toUpperCase())) this.throwHelp(`NAPTR flags are invalid`);

    this.set('flags', val.toUpperCase());
  }

  getFlagsOptions() {
    return new Map([[''], ['S'], ['A'], ['U'], ['P']])
  }

  setService(val) {
    this.set('service', val);
  }

  setRegexp(val) {
    this.set('regexp', val);
  }

  setReplacement(val) {
    this.setTypedValue('fqdn', 'replacement', val);
  }

  /******  IMPORTERS   *******/

  /******  EXPORTERS   *******/

  getWireRdata() {
    const enc = new TextEncoder();
    const flags = enc.encode(this.get('flags'));
    const service = enc.encode(this.get('service'));
    const regexp = enc.encode(this.get('regexp'));
    const replacementBytes = this.wirePackDomain(this.get('replacement'));

    const len = 4 + 1 + flags.length + 1 + service.length + 1 + regexp.length + replacementBytes.length;
    const buf = new Uint8Array(len);
    const view = new DataView(buf.buffer);
    let pos = 0;
    view.setUint16(pos, this.get('order'));
    pos += 2;
    view.setUint16(pos, this.get('preference'));
    pos += 2;
    buf[pos++] = flags.length;
    buf.set(flags, pos);
    pos += flags.length;
    buf[pos++] = service.length;
    buf.set(service, pos);
    pos += service.length;
    buf[pos++] = regexp.length;
    buf.set(regexp, pos);
    pos += regexp.length;
    buf.set(replacementBytes, pos);
    return buf
  }
}

class NS extends RR {
  static typeName = 'NS'
  static typeId = 2
  static RFCs = [1035]
  static tinydnsType = '&'
  static rdataFields = [['dname', 'fqdn']]
  static tags = ['common']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setDname(val) {
    if (!val) this.throwHelp(`NS: dname is required`);

    this.isFullyQualified('NS', 'dname', val);
    this.isValidName('NS', 'dname', val);

    // RFC 4034: letters in the DNS names are lower cased
    this.set('dname', this.lowercaseName(val));
  }

  getDescription() {
    return 'Name Server'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NS',
      dname: 'ns1.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // &fqdn:ip:x:ttl:timestamp:lo
    const [fqdn, _ip, dname, ttl, ts, loc] = tinyline.slice(1).split(':');

    return new NS({
      type: 'NS',
      owner: this.fullyQualify(fqdn),
      dname: this.fullyQualify(/\./.test(dname) ? dname : `${dname}.ns.${fqdn}`),
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return this.wirePackDomain(this.get('dname'))
  }

  toTinydns() {
    return `&${this.getTinyFQDN('owner')}::${this.getTinyFQDN('dname')}:${this.getTinydnsPostamble()}\n`
  }
}

class NSEC extends RR {
  static typeName = 'NSEC'
  static typeId = 47
  static RFCs = [4034]
  static rdataFields = ['next domain', ['type bit maps', 'list']]
  static tags = ['dnssec']

  constructor(opts) {
    super(opts);
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setNextDomain(val) {
    if (!val) this.throwHelp(`NSEC: 'next domain' is required:`);

    this.isFullyQualified('NSEC', 'next domain', val);
    this.isValidName('NSEC', 'next domain', val);

    // RFC 4034: letters in the DNS names are lower cased
    this.set('next domain', this.lowercaseName(val));
  }

  setTypeBitMaps(val) {
    if (!val) this.throwHelp(`NSEC: 'type bit maps' is required`);

    this.set('type bit maps', val);
  }

  getDescription() {
    return 'Next Secure'
  }

  getCanonical() {
    return {
      owner: 'alfa.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NSEC',
      'next domain': 'host.example.com.',
      'type bit maps': 'A MX RRSIG NSEC TYPE1234',
    }
  }

  /******  IMPORTERS   *******/

  fromWire({ owner, cls, ttl, rdata }) {
    const { fqdn: nextDomain, end } = this.wireUnpackDomain(rdata, 0);
    const typeBitMaps = bitmapToTypes(rdata.subarray(end));
    return new NSEC({
      owner,
      ttl,
      class: cls,
      type: 'NSEC',
      'next domain': nextDomain,
      'type bit maps': typeBitMaps,
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const nameBytes = this.wirePackDomain(this.get('next domain'));
    const bitmapBytes = typesToBitmap(this.get('type bit maps'));
    const result = new Uint8Array(nameBytes.length + bitmapBytes.length);
    result.set(nameBytes);
    result.set(bitmapBytes, nameBytes.length);
    return result
  }
}

class NSEC3 extends RR {
  static typeName = 'NSEC3'
  static typeId = 50
  static RFCs = [5155, 9077]
  static rdataFields = [
    ['hash algorithm', 'u8'],
    ['flags', 'u8'],
    ['iterations', 'u16'],
    'salt',
    'next hashed owner name',
    ['type bit maps', 'list'],
  ]
  static tags = ['dnssec']

  constructor(opts) {
    super(opts);
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setHashAlgorithm(val) {
    if (val === undefined) this.throwHelp(`NSEC3: 'hash algorithm' is required`);
    this.is8bitInt('NSEC3', 'hash algorithm', val);
    this.set('hash algorithm', val);
  }

  setFlags(val) {
    if (val === undefined) this.throwHelp(`NSEC3: 'flags' is required`);
    this.is8bitInt('NSEC3', 'flags', val);
    this.set('flags', val);
  }

  setIterations(val) {
    if (val === undefined) this.throwHelp(`NSEC3: 'iterations' is required`);
    this.is16bitInt('NSEC3', 'iterations', val);
    this.set('iterations', val);
  }

  setSalt(val) {
    // RFC 5155 §3.3: case-insensitive hex, or "-" for an empty salt.
    if (val === undefined || val === '') this.throwHelp(`NSEC3: 'salt' is required, "-" when empty`);
    if (val !== '-' && !/^([0-9a-fA-F]{2}){1,255}$/.test(val))
      this.throwHelp(`NSEC3: 'salt' must be hex octets or "-"`);
    this.set('salt', val.toLowerCase());
  }

  setNextHashedOwnerName(val) {
    // RFC 5155 §3.3: unpadded, case-insensitive base32hex.
    if (!val) this.throwHelp(`NSEC3: 'next hashed owner name' is required`);
    const hash = /^[0-9a-v]+$/i.test(val) && base32hexToBytes(val);
    // a partial final quantum would decode to different text
    if (!hash || bytesToBase32hex(hash) !== val.toLowerCase())
      this.throwHelp(`NSEC3: 'next hashed owner name' must be unpadded base32hex`);
    const bytes = hash.length;
    // RFC 5155 §3.2: the Hash Length field is one octet
    if (bytes > 255) this.throwHelp(`NSEC3: 'next hashed owner name' must be <=255 bytes, got ${bytes}`);
    // RFC 5155 §11: algorithm 1 is SHA-1, a 20-byte hash
    if (this.get('hash algorithm') === 1 && bytes !== 20)
      this.throwHelp(`NSEC3: a SHA-1 'next hashed owner name' is 20 bytes, got ${bytes}`);
    this.set('next hashed owner name', val.toLowerCase());
  }

  setTypeBitMaps(val) {
    // RFC 5155 §3.2: an empty non-terminal has no types.
    this.set('type bit maps', val ?? '');
  }

  getDescription() {
    return 'Next Secure'
  }

  getCanonical() {
    return {
      owner: 'test.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NSEC3',
      'hash algorithm': 1,
      flags: 1,
      iterations: 12,
      salt: 'aabbccdd',
      'next hashed owner name': '2vptu5timamqttgl4luu9kg21e0aor3s',
      'type bit maps': 'A RRSIG',
    }
  }

  /******  IMPORTERS   *******/

  fromWire({ owner, cls, ttl, rdata }) {
    return new NSEC3({ ...unpackRdata(rdata), owner, ttl, class: cls, type: 'NSEC3' })
  }

  /******  EXPORTERS   *******/

  // RFC 5155 §3.2: the salt and hash are length-prefixed binary.
  getWireRdata() {
    const salt = this.get('salt') === '-' ? new Uint8Array(0) : hexToBytes(this.get('salt'));
    const hash = base32hexToBytes(this.get('next hashed owner name'));
    const bitmap = typesToBitmap(this.get('type bit maps'));

    const bytes = new Uint8Array(4 + 1 + salt.length + 1 + hash.length + bitmap.length);
    let pos = 0;
    bytes[pos++] = this.get('hash algorithm');
    bytes[pos++] = this.get('flags');
    new DataView(bytes.buffer).setUint16(pos, this.get('iterations'));
    pos += 2;
    bytes[pos++] = salt.length;
    bytes.set(salt, pos);
    pos += salt.length;
    bytes[pos++] = hash.length;
    bytes.set(hash, pos);
    pos += hash.length;
    bytes.set(bitmap, pos);
    return bytes
  }
}

function unpackRdata(bytes) {
  const saltLen = bytes[4];
  const hashLenAt = 5 + saltLen;
  if (bytes.length < 5 || hashLenAt >= bytes.length)
    throw new Error('NSEC3: rdata is truncated before the hash')
  const hashLen = bytes[hashLenAt];
  const hashStart = hashLenAt + 1;
  if (hashLen === 0 || hashStart + hashLen > bytes.length)
    throw new Error('NSEC3: hash length does not fit the rdata')
  return {
    'hash algorithm': bytes[0],
    flags: bytes[1],
    iterations: new DataView(bytes.buffer, bytes.byteOffset).getUint16(2),
    salt: saltLen ? bytesToHex(bytes.subarray(5, hashLenAt)) : '-',
    'next hashed owner name': bytesToBase32hex(bytes.subarray(hashStart, hashStart + hashLen)),
    'type bit maps': bitmapToTypes(bytes.subarray(hashStart + hashLen)),
  }
}

class NSEC3PARAM extends RR {
  static typeName = 'NSEC3PARAM'
  static typeId = 51
  static RFCs = [5155]
  static rdataFields = [['hash algorithm', 'u8'], ['flags', 'u8'], ['iterations', 'u16'], 'salt']
  static tags = ['dnssec']

  constructor(opts) {
    super(opts);
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setHashAlgorithm(val) {
    // Hash Algorithm is a single octet.
    // The Hash Algorithm field is represented as an unsigned decimal integer.
    if (val === undefined || val === null) this.throwHelp(`NSEC3PARAM: 'hash algorithm' is required`);

    this.is8bitInt('NSEC3PARAM', 'hash algorithm', val);

    this.set('hash algorithm', val);
  }

  setFlags(val) {
    // The Flags field is represented as an unsigned decimal integer.
    if (val === undefined || val === null) this.throwHelp(`NSEC3PARAM: 'flags' is required`);

    this.is8bitInt('NSEC3PARAM', 'flags', val);

    this.set('flags', val);
  }

  setIterations(val) {
    // The Iterations field is represented as an unsigned decimal integer. 0-65535
    if (val === undefined || val === null) this.throwHelp(`NSEC3PARAM: 'iterations' is required`);

    this.is16bitInt('NSEC3PARAM', 'iterations', val);

    this.set('iterations', val);
  }

  setSalt(val) {
    // The Salt field is represented as a sequence of case-insensitive
    // hexadecimal digits.  Whitespace is not allowed within the
    // sequence.  The Salt field is represented as "-" (without the
    // quotes) when the Salt Length field has a value of 0
    if (val === '-') {
      this.set('salt', val);
      return
    }

    if (val !== undefined && val !== null && !/^[0-9A-Fa-f]*$/.test(val)) {
      this.throwHelp(`NSEC3PARAM: 'salt' must be hex or '-'`);
    }

    this.set('salt', val);
  }

  getDescription() {
    return 'Next Secure Parameters'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NSEC3PARAM',
      'hash algorithm': 1,
      flags: 1,
      iterations: 12,
      salt: 'aabbccdd',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    // RDATA format: Hash Algorithm (3 octal chars) + Flags (3 octal chars) + Iterations (6 octal chars) + Salt (escaped hex string)
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline);
    if (typeId != this.getTypeId()) this.throwHelp('NSEC3PARAM fromTinydns, invalid n');
    if (rdata.length < 4) {
      this.throwHelp(`NSEC3PARAM: RDATA too short: ${rdata}`);
    }

    // rd may contain actual binary characters (from JS string '\\001' -> char 0x01),
    // so convert via octalToChar and read bytes from a Uint8Array for robust parsing.
    const bytes = octalRdataToBytes(rdata);

    return new NSEC3PARAM({
      owner,
      ttl,
      type: 'NSEC3PARAM',
      'hash algorithm': bytes[0],
      flags: bytes[1],
      iterations: (bytes[2] << 8) | bytes[3],
      salt: bytes[4] === 0 ? '-' : bytesToHex(bytes.subarray(5, 5 + bytes[4])),
      timestamp,
      location,
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const dv = new DataView(rdata.buffer, rdata.byteOffset);
    const saltLen = rdata[4];
    const salt = saltLen === 0 ? '-' : bytesToHex(rdata.subarray(5, 5 + saltLen));
    return new NSEC3PARAM({
      owner,
      ttl,
      class: cls,
      type: 'NSEC3PARAM',
      'hash algorithm': rdata[0],
      flags: rdata[1],
      iterations: dv.getUint16(2),
      salt,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    const salt = this.get('salt');
    const saltOctal =
      salt === '-' ? UInt8toOctal(0) : UInt8toOctal(salt.length / 2) + packHex(salt);

    return this.getTinydnsGeneric(
      UInt8toOctal(this.get('hash algorithm')) +
        UInt8toOctal(this.get('flags')) +
        UInt16toOctal(this.get('iterations')) +
        saltOctal,
    )
  }

  getWireRdata() {
    const salt = this.get('salt');
    const saltBytes = salt === '-' ? new Uint8Array(0) : hexToBytes(salt);
    const bytes = new Uint8Array(4 + 1 + saltBytes.length);
    const dv = new DataView(bytes.buffer, bytes.byteOffset);

    bytes[0] = this.get('hash algorithm');
    bytes[1] = this.get('flags');
    dv.setUint16(2, this.get('iterations'));
    bytes[4] = saltBytes.length;
    bytes.set(saltBytes, 5);

    return bytes
  }
}

class NXT extends RR {
  static typeName = 'NXT'
  static typeId = 30
  static RFCs = [2065]
  static rdataFields = ['next domain', ['type bit map', 'list']]
  static tags = ['obsolete']

  constructor(opts) {
    super(opts);
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/
  setNextDomain(val) {
    if (!val) this.throwHelp(`NXT: 'next domain' is required`);

    this.isFullyQualified('NXT', 'next domain', val);
    this.isValidName('NXT', 'next domain', val);

    // RFC 4034: letters in the DNS names are lower cased
    this.set('next domain', this.lowercaseName(val));
  }

  setTypeBitMap(val) {
    if (!val) this.throwHelp(`NXT: 'type bit map' is required`);

    this.set('type bit map', val);
  }

  getDescription() {
    return 'Next Secure'
  }

  getCanonical() {
    return {
      owner: 'big.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'NXT',
      'next domain': 'host.example.com.',
      'type bit map': 'A MX NXT',
    }
  }

  /******  IMPORTERS   *******/

  fromWire({ owner, cls, ttl, rdata }) {
    const { fqdn: nextDomain, end } = this.wireUnpackDomain(rdata, 0);
    const typeBitMap = nxtBitmapToTypes(rdata.subarray(end));
    return new NXT({
      owner,
      ttl,
      class: cls,
      type: 'NXT',
      'next domain': nextDomain,
      'type bit map': typeBitMap,
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const nameBytes = this.wirePackDomain(this.get('next domain'));
    const bitmapBytes = typesToNxtBitmap(this.get('type bit map'));
    const result = new Uint8Array(nameBytes.length + bitmapBytes.length);
    result.set(nameBytes);
    result.set(bitmapBytes, nameBytes.length);
    return result
  }
}

function nxtBitmapToTypes(bitmap) {
  const DNS_TYPE_NAMES = Object.fromEntries(Object.entries(DNS_TYPE_IDS).map(([k, v]) => [v, k]));
  const types = [];
  for (let i = 0; i < bitmap.length; i++) {
    const byte = bitmap[i];
    for (let bit = 0; bit < 8; bit++) {
      if (byte & (0x80 >> bit)) {
        const typeId = i * 8 + bit;
        types.push(DNS_TYPE_NAMES[typeId] ?? `TYPE${typeId}`);
      }
    }
  }
  return types.join(' ')
}

function typesToNxtBitmap(typeNamesStr) {
  const bitmap = new Uint8Array(16);
  for (const name of typeNamesStr.trim().split(/\s+/)) {
    const id = /^TYPE\d+$/i.test(name) ? parseInt(name.slice(4), 10) : DNS_TYPE_IDS[name.toUpperCase()];
    if (id !== undefined && id < 128) bitmap[Math.floor(id / 8)] |= 0x80 >> (id % 8);
  }
  let len = bitmap.length;
  while (len > 0 && bitmap[len - 1] === 0) len--;
  return bitmap.slice(0, len)
}

class OPENPGPKEY extends RR {
  static typeName = 'OPENPGPKEY'
  static typeId = 61
  static RFCs = [4880, 7929]
  static rdataFields = [['public key', 'base64']]
  static tags = ['security']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setPublicKey(val) {
    this.isBase64('OPENPGPKEY', 'public key', val);
    this.set('public key', val);
  }

  getDescription() {
    return 'OpenPGP Public Key'
  }

  getCanonical() {
    return {
      owner: 'matt.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'OPENPGPKEY',
      'public key':
        'AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwIXAqcOTiW7iHnQt5hwVAAAAA==',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline);
    if (typeId != this.getTypeId()) this.throwHelp('OPENPGPKEY fromTinydns, invalid n');
    return new OPENPGPKEY({
      owner,
      ttl,
      type: 'OPENPGPKEY',
      'public key': octalToBase64(rdata),
      timestamp,
      location,
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric(base64toOctal(this.get('public key')))
  }

  getWireRdata() {
    return base64ToBytes(this.get('public key'))
  }
}

class PTR extends RR {
  static typeName = 'PTR'
  static typeId = 12
  static RFCs = [1035]
  static tinydnsType = '^'
  static rdataFields = [['dname', 'fqdn']]
  static tags = ['common']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setDname(val) {
    this.isFullyQualified('PTR', 'dname', val);
    this.isValidName('PTR', 'dname', val);

    // RFC 4034: letters in the DNS names are lower cased
    this.set('dname', this.lowercaseName(val));
  }

  getDescription() {
    return 'Pointer'
  }

  getCanonical() {
    return {
      owner: '2.2.0.192.in-addr.arpa.',
      ttl: 3600,
      class: 'IN',
      type: 'PTR',
      dname: 'host.example.com.',
    }
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return this.wirePackDomain(this.get('dname'))
  }
}

class RP extends RR {
  static typeName = 'RP'
  static rdataFields = [
    ['mbox', 'fqdn'],
    ['txt', 'fqdn'],
  ]

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setMbox(val) {
    this.setTypedValue('fqdn', 'mbox', val);
  }

  setTxt(val) {
    this.setTypedValue('fqdn', 'txt', val);
  }

  getDescription() {
    return 'Responsible Person'
  }
  static tags = ['obsolete']
  static RFCs = [1183]
  static typeId = 17
  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'RP',
      mbox: 'admin.example.com.',
      txt: 'info.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    const [owner, _typeId, rdata, ttl, ts, loc] = tinyline.slice(1).split(':');

    const [mbox, consumed] = unpackDomainName(rdata);
    const txt = unpackDomainName(rdata.slice(consumed))[0];

    return new RP({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      type: 'RP',
      mbox,
      txt,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const mbox = this.wirePackDomain(this.get('mbox'));
    const txt = this.wirePackDomain(this.get('txt'));
    const result = new Uint8Array(mbox.length + txt.length);
    result.set(mbox, 0);
    result.set(txt, mbox.length);
    return result
  }

  toTinydns() {
    return this.getTinydnsGeneric(
      packDomainName(this.get('mbox')) + packDomainName(this.get('txt')),
    )
  }
}

class RRSIG extends RR {
  static typeName = 'RRSIG'
  static typeId = 46
  static RFCs = [4034]
  static rdataFields = [
    ['type covered', 'rrtype'],
    ['algorithm', 'u8'],
    ['labels', 'u8'],
    ['original ttl', 'u32'],
    ['signature expiration', 'u32'],
    ['signature inception', 'u32'],
    ['key tag', 'u16'],
    ['signers name', 'fqdn'],
    ['signature', 'base64'],
  ]
  static tags = ['dnssec']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setTypeCovered(val) {
    if (!val && val !== 0) this.throwHelp(`RRSIG: 'type covered' is required`);
    this.setTypedValue('rrtype', 'type covered', val);
  }

  setAlgorithm(val) {
    // a 1 octet Algorithm field
    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`RRSIG: algorithm invalid`);

    this.set('algorithm', val);
  }

  // RFC 4034 §3.1.3: labels counts the original owner's labels, less a leading
  // `*`, and the signer is an ancestor of that owner.
  setLabels(val) {
    this.setTypedValue('u8', 'labels', val);
    const owner = nameToLabels(this.get('owner'));
    const ownerLabels = owner[0]?.length === 1 && owner[0][0] === 0x2a ? owner.length - 1 : owner.length;
    if (val > ownerLabels) this.throwHelp(`RRSIG: labels (${val}) exceeds the owner's ${ownerLabels}`);
  }

  setOriginalTtl(val) {
    this.setTypedValue('u32', 'original ttl', val);
  }

  setSignatureExpiration(val) {
    this.setSignatureTime('signature expiration', val);
  }

  setSignatureInception(val) {
    this.setSignatureTime('signature inception', val);
  }

  setKeyTag(val) {
    this.setTypedValue('u16', 'key tag', val);
  }

  setSignersName(val) {
    this.setTypedValue('fqdn', 'signers name', val);
    const signer = nameToLabels(this.get('signers name'));
    if (signer.length > this.get('labels'))
      this.throwHelp(
        `RRSIG: signers name has ${signer.length} labels, more than labels (${this.get('labels')})`,
      );
    // the signer is the owner or an ancestor: its labels end the owner's, ASCII case aside
    const owner = nameToLabels(this.get('owner'));
    const fold = (label) => String.fromCharCode(...label).replace(/[A-Z]/g, (c) => c.toLowerCase());
    const offset = owner.length - signer.length;
    if (offset < 0 || signer.some((label, i) => fold(label) !== fold(owner[offset + i])))
      this.throwHelp(`RRSIG: signers name ${val} is not the owner or an ancestor of it`);
  }

  setSignature(val) {
    // RFC 4034 §3.2: presentation form is base64; wire form is decoded bytes.
    this.isBase64('RRSIG', 'signature', String(val).replace(/[\s()]/g, ''));
    this.set('signature', val);
  }

  getAlgorithmOptions() {
    // IANA DNSSEC Algorithm Numbers
    // https://www.iana.org/assignments/dns-sec-alg-numbers/
    return new Map([
      [1, 'RSA/MD5'],
      [2, 'DH'],
      [3, 'DSA/SHA-1'],
      [4, 'EC'],
      [5, 'RSA/SHA-1'],
      [6, 'DSA-NSEC3-SHA1'],
      [7, 'RSASHA1-NSEC3-SHA1'],
      [8, 'RSA/SHA-256'],
      [10, 'RSA/SHA-512'],
      [13, 'ECDSA P-256/SHA-256'],
      [14, 'ECDSA P-384/SHA-384'],
      [15, 'Ed25519'],
      [16, 'Ed448'],
      [253],
      [254],
    ])
  }

  getDescription() {
    return 'Resource Record Signature'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'RRSIG',
      'type covered': 1,
      algorithm: 5,
      labels: 2,
      'original ttl': 3600,
      'signature expiration': 1045053120,
      'signature inception': 1042461120,
      'key tag': 12345,
      'signers name': 'example.com.',
      signature:
        'oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTrPYGv07h108dUKGMeDPKijVCHX3DDKdfb' +
        '+v6oB9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3tGNazPwQKkRN20XPXV6nwwfoXmJQb' +
        'sLNrLfkGJ5D6fwFm8nN+6pBzeDQfsS3Ap3o=',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':');
    if (parseInt(n, 10) !== this.getTypeId()) this.throwHelp('RRSIG fromTinydns, invalid n');

    const bytes = Uint8Array.from(octalToChar(rdata), (c) => c.charCodeAt(0));
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const typeCovered = dv.getUint16(0);
    const algorithm = bytes[2];
    const labels = bytes[3];
    const originalTtl = dv.getUint32(4);
    const signatureExpiration = dv.getUint32(8);
    const signatureInception = dv.getUint32(12);
    const keyTag = dv.getUint16(16);

    let pos = 18;
    const labelArr = [];
    while (pos < bytes.length) {
      const len = bytes[pos++];
      if (len === 0) break
      labelArr.push(new TextDecoder().decode(bytes.subarray(pos, pos + len)));
      pos += len;
    }
    const signersName = `${labelArr.join('.')}.`;
    const signature = bytesToBase64(bytes.subarray(pos));

    return new RRSIG({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'RRSIG',
      'type covered': typeCovered,
      algorithm,
      labels,
      'original ttl': originalTtl,
      'signature expiration': signatureExpiration,
      'signature inception': signatureInception,
      'key tag': keyTag,
      'signers name': signersName,
      signature,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    return this.getTinydnsGeneric(
      UInt16toOctal(this.get('type covered')) +
        UInt8toOctal(this.get('algorithm')) +
        UInt8toOctal(this.get('labels')) +
        UInt32toOctal(this.get('original ttl')) +
        UInt32toOctal(this.get('signature expiration')) +
        UInt32toOctal(this.get('signature inception')) +
        UInt16toOctal(this.get('key tag')) +
        packDomainName(this.get('signers name')) +
        base64toOctal(this.get('signature').replace(/[\s()]/g, '')),
    )
  }

  getWireRdata() {
    const signerBytes = wirePackDomain(this.get('signers name'));
    const sigBytes = base64ToBytes(this.get('signature').replace(/[\s()]/g, ''));

    const totalLen = 2 + 1 + 1 + 4 + 4 + 4 + 2 + signerBytes.length + sigBytes.length;
    const bytes = new Uint8Array(totalLen);
    const dv = new DataView(bytes.buffer, bytes.byteOffset);

    let pos = 0;
    dv.setUint16(pos, this.get('type covered'));
    pos += 2;
    bytes[pos++] = this.get('algorithm');
    bytes[pos++] = this.get('labels');
    dv.setUint32(pos, this.get('original ttl'));
    pos += 4;
    dv.setUint32(pos, this.get('signature expiration'));
    pos += 4;
    dv.setUint32(pos, this.get('signature inception'));
    pos += 4;
    dv.setUint16(pos, this.get('key tag'));
    pos += 2;
    bytes.set(signerBytes, pos);
    pos += signerBytes.length;
    bytes.set(sigBytes, pos);

    return bytes
  }
}

class SIG extends RR {
  static typeName = 'SIG'
  static typeId = 24
  static RFCs = [2535, 3755]
  static rdataFields = [
    ['type covered', 'rrtype'],
    ['algorithm', 'u8'],
    ['labels', 'u8'],
    ['original ttl', 'u32'],
    ['signature expiration', 'u32'],
    ['signature inception', 'u32'],
    ['key tag', 'u16'],
    ['signers name', 'fqdn'],
    ['signature', 'base64'],
  ]
  static tags = ['obsolete']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setTypeCovered(val) {
    if (!val && val !== 0) this.throwHelp(`SIG: 'type covered' is required`);
    this.setTypedValue('rrtype', 'type covered', val);
  }

  setAlgorithm(val) {
    // a 1 octet Algorithm field
    this.is8bitInt('SIG', 'algorithm', val);

    this.set('algorithm', val);
  }

  setLabels(val) {
    // a 1 octet Labels field
    this.is8bitInt('SIG', 'labels', val);

    this.set('labels', val);
  }

  setOriginalTtl(val) {
    // a 4 octet Original TTL field
    this.is32bitInt('SIG', 'original ttl', val);

    this.set('original ttl', val);
  }

  setSignatureExpiration(val) {
    this.setSignatureTime('signature expiration', val);
  }

  setSignatureInception(val) {
    this.setSignatureTime('signature inception', val);
  }

  setKeyTag(val) {
    // a 2 octet Key tag
    this.set('key tag', val);
  }

  setSignersName(val) {
    this.setTypedValue('fqdn', 'signers name', val);
  }

  setSignature(val) {
    this.isBase64('SIG', 'signature', val);
    this.set('signature', val);
  }

  getDescription() {
    return 'Signature'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SIG',
      'type covered': 1,
      algorithm: 5,
      labels: 3,
      'original ttl': 3600,
      'signature expiration': 1045053120,
      'signature inception': 1042461120,
      'key tag': 12345,
      'signers name': 'example.com.',
      signature: 'AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8no',
    }
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric(
      UInt16toOctal(this.get('type covered')) +
        UInt8toOctal(this.get('algorithm')) +
        UInt8toOctal(this.get('labels')) +
        UInt32toOctal(this.get('original ttl')) +
        UInt32toOctal(this.get('signature expiration')) +
        UInt32toOctal(this.get('signature inception')) +
        UInt16toOctal(this.get('key tag')) +
        packDomainName(this.get('signers name')) +
        base64toOctal(this.get('signature')),
    )
  }

  getWireRdata() {
    const signerBytes = wirePackDomain(this.get('signers name'));
    const sigBytes = base64ToBytes(this.get('signature'));

    const totalLen = 2 + 1 + 1 + 4 + 4 + 4 + 2 + signerBytes.length + sigBytes.length;
    const bytes = new Uint8Array(totalLen);
    const dv = new DataView(bytes.buffer, bytes.byteOffset);

    let pos = 0;
    dv.setUint16(pos, this.get('type covered'));
    pos += 2;
    bytes[pos++] = this.get('algorithm');
    bytes[pos++] = this.get('labels');
    dv.setUint32(pos, this.get('original ttl'));
    pos += 4;
    dv.setUint32(pos, this.get('signature expiration'));
    pos += 4;
    dv.setUint32(pos, this.get('signature inception'));
    pos += 4;
    dv.setUint16(pos, this.get('key tag'));
    pos += 2;
    bytes.set(signerBytes, pos);
    pos += signerBytes.length;
    bytes.set(sigBytes, pos);

    return bytes
  }

  fromTinydns({ tinyline }) {
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline);
    if (parseInt(typeId, 10) !== this.getTypeId()) this.throwHelp('SIG fromTinydns, invalid n');

    const bytes = octalRdataToBytes(rdata);
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    const typeCovered = dv.getUint16(0);
    const algorithm = bytes[2];
    const labels = bytes[3];
    const originalTtl = dv.getUint32(4);
    const signatureExpiration = dv.getUint32(8);
    const signatureInception = dv.getUint32(12);
    const keyTag = dv.getUint16(16);

    // parse signers name from binary starting at offset 18
    let pos = 18;
    const labelsArr = [];
    while (pos < bytes.length) {
      const len = bytes[pos++];
      if (len === 0) break
      labelsArr.push(new TextDecoder().decode(bytes.subarray(pos, pos + len)));
      pos += len;
    }
    const signersName = `${labelsArr.join('.')}.`;

    const signature = bytesToBase64(bytes.subarray(pos));

    return new SIG({
      owner,
      ttl,
      type: 'SIG',
      'type covered': typeCovered,
      algorithm,
      labels,
      'original ttl': originalTtl,
      'signature expiration': signatureExpiration,
      'signature inception': signatureInception,
      'key tag': keyTag,
      'signers name': signersName,
      signature,
      timestamp,
      location,
    })
  }

  toBind(zone_opts) {
    // RFC 2535 §7.2 presents SIG times only as YYYYMMDDHHmmSS; BIND rejects integers.
    const rdata = this.getRdataFields().map((f) => {
      if (f === 'signature expiration' || f === 'signature inception') return formatSignatureTime(this.get(f))
      if (f === 'signers name') return this.getFQDN(f, zone_opts)
      if (f === 'type covered') return typeIdToName(this.get(f))
      return this.get(f)
    });
    return `${this.getPrefix(zone_opts)}\t${rdata.join('\t')}\n`
  }
}

// RFC 6698 §2.1.3: matching types 1 and 2 are SHA-256 and SHA-512 digests.
const DIGEST_BYTES$1 = { 1: 32, 2: 64 };

class SMIMEA extends RR {
  static typeName = 'SMIMEA'
  static typeId = 53
  static RFCs = [8162]
  static rdataFields = [
    ['certificate usage', 'u8'],
    ['selector', 'u8'],
    ['matching type', 'u8'],
    ['certificate association data', 'hex'],
  ]
  static tags = ['security']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setCertificateUsage(val) {
    if (!this.getCertificateUsageOptions().has(val)) this.throwHelp(`SMIMEA: certificate usage invalid`);

    this.set('certificate usage', val);
  }

  getCertificateUsageOptions() {
    return new Map([
      [0, 'CA certificate'],
      [1, 'an end entity certificate'],
      [2, 'the trust anchor'],
      [3, 'domain-issued certificate'],
    ])
  }

  setSelector(val) {
    if (!this.getSelectorOptions().has(val)) this.throwHelp(`SMIMEA: selector invalid`);

    this.set('selector', val);
  }

  getSelectorOptions() {
    return new Map([
      [0, 'Full certificate'],
      [1, 'SubjectPublicKeyInfo'],
    ])
  }

  setMatchingType(val) {
    if (!this.getMatchingTypeOptions().has(val)) this.throwHelp(`SMIMEA: matching type`);
    const data = this.get('certificate association data');
    if (data !== undefined) this.isHexDigest('certificate association data', data, DIGEST_BYTES$1[val]);
    this.set('matching type', val);
  }

  getMatchingTypeOptions() {
    return new Map([
      [0, 'Exact match'],
      [1, 'SHA-256 hash'],
      [2, 'SHA-512 hash'],
    ])
  }

  setCertificateAssociationData(val) {
    this.isHexDigest('certificate association data', val, DIGEST_BYTES$1[this.get('matching type')]);
    this.set('certificate association data', val);
  }

  getDescription() {
    return 'S/MIME cert association'
  }

  getCanonical() {
    return {
      owner: '_443._tcp.www.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SMIMEA',
      'certificate usage': 0,
      selector: 0,
      'matching type': 1,
      'certificate association data': 'D2ABDE240D7CD3EE6B4B28C54DF034B97983A1D16E8A410E4561CB106618E971',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    const { owner, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline);
    const binaryRdata = octalRdataToBytes(rdata);

    return new SMIMEA({
      owner,
      ttl,
      type: 'SMIMEA',
      'certificate usage': binaryRdata[0],
      selector: binaryRdata[1],
      'matching type': binaryRdata[2],
      'certificate association data': bytesToHex(binaryRdata.subarray(3)),
      timestamp,
      location,
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric(
      UInt8toOctal(this.get('certificate usage')) +
        UInt8toOctal(this.get('selector')) +
        UInt8toOctal(this.get('matching type')) +
        packHex(this.get('certificate association data').replace(/[\s()]/g, '')),
    )
  }

  getWireRdata() {
    const cadBytes = hexToBytes(this.get('certificate association data').replace(/[\s()]/g, ''));
    const bytes = new Uint8Array(3 + cadBytes.length);
    bytes[0] = this.get('certificate usage');
    bytes[1] = this.get('selector');
    bytes[2] = this.get('matching type');
    bytes.set(cadBytes, 3);
    return bytes
  }
}

class SOA extends RR {
  static typeName = 'SOA'
  static typeId = 6
  static RFCs = [1035, 2308]
  static tinydnsType = 'Z'
  static rdataFields = [
    ['mname', 'fqdn'],
    ['rname', 'fqdn'],
    ['serial', 'u32'],
    ['refresh', 'u32'],
    ['retry', 'u32'],
    ['expire', 'u32'],
    ['minimum', 'u32'],
  ]
  static tags = ['common']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setMinimum(val) {
    // minimum (used for negative caching, since RFC 2308)
    // RFC 1912 sugggests 1-5 days
    // RIPE recommends 3600 (1 hour)
    this.is32bitInt('SOA', 'minimum', val);

    this.set('minimum', val);
  }

  setMname(val) {
    // MNAME (primary NS)
    this.isValidName('SOA', 'MNAME', val);
    this.isFullyQualified('SOA', 'MNAME', val);

    // RFC 4034: letters in the DNS names are lower cased
    this.set('mname', this.lowercaseName(val));
  }

  setRname(val) {
    // RNAME (email of admin)  (escape . with \)
    this.isValidName('SOA', 'RNAME', val);
    this.isFullyQualified('SOA', 'RNAME', val);
    if (/@/.test(val)) this.throwHelp(`SOA rname replaces @ with a . (dot)`);

    // RFC 4034: letters in the DNS names are lower cased
    this.set('rname', this.lowercaseName(val));
  }

  setSerial(val) {
    this.is32bitInt('SOA', 'serial', val);

    this.set('serial', val);
  }

  setRefresh(val) {
    // refresh (seconds after which to check with master for update)
    // RFC 1912 suggests 20 min to 12 hours
    // RIPE recommends 86400 (24 hours)
    this.is32bitInt('SOA', 'refresh', val);

    this.set('refresh', val);
  }

  setRetry(val) {
    // seconds after which to retry serial # update
    // RIPE recommends 7200 seconds (2 hours)

    this.is32bitInt('SOA', 'retry', val);

    this.set('retry', val);
  }

  setExpire(val) {
    // seconds after which secondary should drop zone if no master response
    // RFC 1912 suggests 2-4 weeks
    // RIPE suggests 3600000 (1,000 hours, 6 weeks)
    this.is32bitInt('SOA', 'expire', val);

    this.set('expire', val);
  }

  getDescription() {
    return 'Start Of Authority'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SOA',
      mname: 'ns1.example.com.',
      rname: 'admin.example.com.',
      serial: 2023051001,
      refresh: 7200,
      retry: 3600,
      expire: 1209600,
      minimum: 3600,
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // Zfqdn:mname:rname:ser:ref:ret:exp:min:ttl:time:lo
    const [fqdn, mname, rname, ser, ref, ret, exp, min, ttl, ts, loc] = tinyline.slice(1).split(':');

    return new SOA({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'SOA',
      mname: this.fullyQualify(mname),
      rname: this.fullyQualify(rname),
      serial: parseInt(ser ?? this.default?.serial, 10),
      refresh: parseInt(ref, 10) || 16384,
      retry: parseInt(ret, 10) || 2048,
      expire: parseInt(exp, 10) || 1048576,
      minimum: parseInt(min, 10) || 2560,
      timestamp: parseInt(ts) || '',
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/
  toMaraDNS() {
    this.assertClassIN('MaraDNS');
    return `${this.get('owner')}\t+${this.get('ttl')}\tSOA\t${this.getFields('rdata')
      .map((f) => this.getQuoted(f))
      .join('\t')} ~\n`
  }

  getWireRdata() {
    const mname = this.wirePackDomain(this.get('mname'));
    const rname = this.wirePackDomain(this.get('rname'));
    const result = new Uint8Array(mname.length + rname.length + 20);
    let offset = 0;
    result.set(mname, offset);
    offset += mname.length;
    result.set(rname, offset);
    offset += rname.length;
    const view = new DataView(result.buffer, offset);
    view.setUint32(0, this.get('serial'));
    view.setUint32(4, this.get('refresh'));
    view.setUint32(8, this.get('retry'));
    view.setUint32(12, this.get('expire'));
    view.setUint32(16, this.get('minimum'));
    return result
  }

  toTinydns() {
    return `Z${this.getTinyFQDN('owner')}:${this.getTinyFQDN('mname')}:${this.getTinyFQDN('rname')}:${this.getEmpty('serial')}:${this.getEmpty('refresh')}:${this.getEmpty('retry')}:${this.getEmpty('expire')}:${this.getEmpty('minimum')}:${this.getTinydnsPostamble()}\n`
  }
}

class TXT extends RR {
  static typeName = 'TXT'
  static typeId = 16
  static RFCs = [1035, 4408, 7208, 6376]
  static tinydnsType = "'"
  static rdataFields = [['data', 'charstrs']]
  static tags = ['common']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setData(val) {
    this.set('data', val);
  }

  getDescription() {
    return 'Text'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'TXT',
      data: 'v=spf1 mx -all',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    if (tinyline[0] !== "'") return this.fromTinydnsWire({ tinyline })

    // 'fqdn:s:ttl:timestamp:lo, which tinydns-data stores as strings of at most 127 bytes
    const [fqdn, s, ttl, ts, loc] = tinyline.slice(1).split(':');
    const bytes = octalRdataToBytes(s);
    const utf8 = new TextDecoder('utf-8', { fatal: true });
    const strings = [];
    for (let i = 0; i < bytes.length; i += TINYDNS_TXT_CHUNK) {
      strings.push(utf8.decode(bytes.subarray(i, i + TINYDNS_TXT_CHUNK)));
    }

    return new this.constructor({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'TXT',
      data: strings.length > 1 ? strings : (strings[0] ?? ''),
      timestamp: ts,
      location: loc?.trim() || '',
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    return `${this.getPrefix(zone_opts)}\t"${asQuotedStrings(this.get('data'))}"\n`
  }

  toMaraDNS() {
    this.assertClassIN('MaraDNS');
    // csv2_txt(5): an unquoted ';' separates chunks.
    const data = asQuotedStrings(this.get('data'), { quote: quoteCharString, delimiter: ';' });
    return `${this.get('owner')}\t+${this.get('ttl')}\t${this.get('type')}\t${data} ~\n`
  }

  getWireRdata() {
    // RFC 1035 §3.3.14: TXT rdata is one or more <character-string>s, each up
    // to 255 bytes. An array preserves explicit boundaries between strings;
    // each element MUST be <= 255 UTF-8 bytes, otherwise we would silently
    // split it and the boundary the caller asked us to preserve would be lost.
    // A single string is auto-chunked at 255-byte UTF-8 boundaries.
    const data = this.get('data');
    if (Array.isArray(data)) {
      const enc = new TextEncoder();
      const buffers = data.map((s, i) => {
        if (enc.encode(s).length > 255) {
          this.throwHelp(
            `TXT: array element ${i} exceeds 255 bytes; split it yourself or pass a single string to auto-chunk`,
          );
        }
        return packStringWire(s)
      });
      const total = buffers.reduce((n, b) => n + b.length, 0);
      const out = new Uint8Array(total);
      let off = 0;
      for (const b of buffers) {
        out.set(b, off);
        off += b.length;
      }
      return out
    }
    return packStringWire(data)
  }

  // A ' line can hold only one string of 1 to 127 bytes, since tinydns-data
  // splits longer text at 127; anything else takes the generic form.
  toTinydns() {
    const data = this.get('data');
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : null;
    if (!this.constructor.tinydnsType || !bytes?.length || bytes.length > TINYDNS_TXT_CHUNK)
      return this.getTinydnsGeneric(bytesToTinydnsText(this.getWireRdata()))
    return `'${this.getTinyFQDN('owner')}:${bytesToTinydnsText(bytes)}:${this.getTinydnsPostamble()}\n`
  }
}

// RFC 1035 character-strings are 255 bytes max. The limit counts wire bytes,
// so chunk the unescaped value by UTF-8 bytes and escape each chunk afterwards.
function asQuotedStrings(data, { quote = escapeCharString, delimiter = '" "' } = {}) {
  const enc = new TextEncoder();

  if (Array.isArray(data)) {
    const anyTooLong = data.some((s) => enc.encode(s).length > 255);
    if (!anyTooLong) return data.map(quote).join(delimiter)
    return chunkByBytes(data.join(''), 255).map(quote).join(delimiter)
  }

  if (enc.encode(data).length <= 255) return quote(data)
  return chunkByBytes(data, 255).map(quote).join(delimiter)
}

function chunkByBytes(str, maxBytes) {
  const bytes = new TextEncoder().encode(str);
  const dec = new TextDecoder();
  const chunks = [];
  let start = 0;
  while (start < bytes.length) {
    let end = Math.min(start + maxBytes, bytes.length);
    // back up to a UTF-8 codepoint boundary so decode() returns whole chars
    while (end < bytes.length && (bytes[end] & 0xc0) === 0x80) end--;
    chunks.push(dec.decode(bytes.subarray(start, end)));
    start = end;
  }
  return chunks
}

function packStringWire(str) {
  if (str === '') return new Uint8Array([0])

  const enc = new TextEncoder();
  const chunks = chunkByBytes(str, 255).map((c) => enc.encode(c));
  const buf = new Uint8Array(chunks.reduce((n, c) => n + 1 + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    buf[offset++] = chunk.length;
    buf.set(chunk, offset);
    offset += chunk.length;
  }
  return buf
}

const TINYDNS_TXT_CHUNK = 127;

// obsoleted by RFC 7208


class SPF extends TXT {
  static typeName = 'SPF'
  static typeId = 99
  // tinydns has no SPF line; it takes the generic `:` form.
  static tinydnsType = undefined
  static RFCs = [4408, 7208]
  static rdataFields = [['data', 'charstrs']]
  static tags = ['obsolete']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setData(val) {
    this.set('data', val);
  }

  getDescription() {
    return 'Sender Policy Framework'
  }
  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SPF',
      data: 'v=spf1 mx -all',
    }
  }

  /******  EXPORTERS   *******/
  getWireRdata() {
    return super.getWireRdata()
  }
}

class SRV extends RR {
  static typeName = 'SRV'
  static typeId = 33
  static RFCs = [2782]
  static rdataFields = [
    ['priority', 'u16'],
    ['weight', 'u16'],
    ['port', 'u16'],
    ['target', 'fqdn'],
  ]
  static tags = ['common']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.setTypedValue('u16', 'priority', val);
  }

  setWeight(val) {
    this.setTypedValue('u16', 'weight', val);
  }

  setPort(val) {
    this.setTypedValue('u16', 'port', val);
  }

  setTarget(val) {
    this.setTypedValue('fqdn', 'target', val);
  }

  getDescription() {
    return 'Service'
  }

  getCanonical() {
    return {
      owner: '_imaps._tcp.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SRV',
      priority: 10,
      weight: 10,
      port: 993,
      target: 'mail.example.com.',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    const str = tinyline;
    let fqdn, addr, port, pri, weight, ttl, ts, loc, n, rdata;

    if (str[0] === 'S') {
[fqdn, addr, port, pri, weight, ttl, ts, loc] = str.slice(1).split(':');
    } else {
[fqdn, n, rdata, ttl, ts, loc] = str.slice(1).split(':');
      if (n != 33) this.throwHelp('SRV fromTinydns: invalid n');

      pri = octalToUInt16(rdata.slice(0, 8));
      weight = octalToUInt16(rdata.slice(8, 16));
      port = octalToUInt16(rdata.slice(16, 24));
      addr = unpackDomainName(rdata.slice(24))[0];
    }

    return new SRV({
      owner: this.fullyQualify(fqdn),
      ttl: parseInt(ttl, 10),
      type: 'SRV',
      priority: parseInt(pri, 10),
      weight: parseInt(weight, 10),
      port: parseInt(port, 10),
      target: this.fullyQualify(addr),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const target = this.wirePackDomain(this.get('target'));
    const result = new Uint8Array(6 + target.length);
    const dv = new DataView(result.buffer);
    dv.setUint16(0, this.get('priority'));
    dv.setUint16(2, this.get('weight'));
    dv.setUint16(4, this.get('port'));
    result.set(target, 6);
    return result
  }

  toTinydns() {
    let rdata = '';

    for (const e of ['priority', 'weight', 'port']) {
      rdata += UInt16toOctal(this.get(e));
    }

    rdata += packDomainName(this.get('target'));

    return this.getTinydnsGeneric(rdata)
  }
}

// RFC 4255 §3.1.3, RFC 6594: SHA-1 and SHA-256 fingerprints.
const FINGERPRINT_BYTES = { 1: 20, 2: 32 };

class SSHFP extends RR {
  static typeName = 'SSHFP'
  static typeId = 44
  static RFCs = [4255, 7479, 8709]
  static rdataFields = [
    ['algorithm', 'u8'],
    ['fptype', 'u8'],
    ['fingerprint', 'hex'],
  ]
  static tags = ['security']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setAlgorithm(val) {
    if (!this.getAlgorithmOptions().has(val)) this.throwHelp(`SSHFP: algorithm invalid`);
    this.setTypedValue('u8', 'algorithm', val);
  }

  setFptype(val) {
    if (!this.getFptypeOptions().has(val)) this.throwHelp(`SSHFP: fptype invalid`);
    if (this.get('fingerprint') !== undefined)
      this.isHexDigest('fingerprint', this.get('fingerprint'), FINGERPRINT_BYTES[val]);
    this.setTypedValue('u8', 'fptype', val);
  }

  setFingerprint(val) {
    this.isHexDigest('fingerprint', val, FINGERPRINT_BYTES[this.get('fptype')]);
    this.set('fingerprint', val);
  }

  getAlgorithmOptions() {
    return new Map([
      [0, 'reserved'],
      [1, 'RSA'],
      [2, 'DSA'],
      [3, 'ECDSA'],
      [4, 'Ed25519'],
      [6, 'Ed448'],
    ])
  }

  getFptypeOptions() {
    return new Map([
      [0, 'reserved'],
      [1, 'SHA-1'],
      [2, 'SHA-256'],
    ])
  }

  getDescription() {
    return 'Secure Shell Key Fingerprints'
  }

  getCanonical() {
    return {
      owner: 'mail.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SSHFP',
      algorithm: 2,
      fptype: 1,
      fingerprint: '123456789abcdef6789abcdf6789abdf6789abcd',
    }
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // SSHFP via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline);
    if (typeId != this.getTypeId()) this.throwHelp('SSHFP fromTinydns, invalid n');

    return new SSHFP({
      owner,
      ttl,
      type: 'SSHFP',
      algorithm: octalToUInt8(rdata.slice(0, 4)),
      fptype: octalToUInt8(rdata.slice(4, 8)),
      fingerprint: octalToHex(rdata.slice(8)),
      timestamp,
      location,
    })
  }

  /******  EXPORTERS   *******/

  toTinydns() {
    return this.getTinydnsGeneric(
      UInt8toOctal(this.get('algorithm')) +
        UInt8toOctal(this.get('fptype')) +
        packHex(this.get('fingerprint')),
    )
  }

  getWireRdata() {
    const bytes = new Uint8Array(2 + hexToBytes(this.get('fingerprint')).length);
    bytes[0] = this.get('algorithm');
    bytes[1] = this.get('fptype');
    bytes.set(hexToBytes(this.get('fingerprint')), 2);
    return bytes
  }
}

class SVCB extends RR {
  static typeName = 'SVCB'
  static typeId = 64
  static RFCs = [9460]
  static rdataFields = [
    ['priority', 'u16'],
    ['target name', 'fqdn'],
    ['params', 'svcparams'],
  ]

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.is16bitInt('SVCB', 'priority', val);

    this.set('priority', val);
  }

  setTargetName(val) {
    if (!val) this.throwHelp('SVCB: target name is required');
    this.isFullyQualified('SVCB', 'target name', val);
    this.isValidName('SVCB', 'target name', val);

    // RFC 4034: letters in the DNS names are lower cased
    this.set('target name', this.lowercaseName(val));
  }

  setParams(val) {
    this.setTypedValue('svcparams', 'params', val);
  }

  getDescription() {
    return 'Service Binding'
  }

  getCanonical() {
    return {
      owner: '_8443._foo.api.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'SVCB',
      priority: 1,
      'target name': 'svc4.example.net.',
      params: 'alpn="h2,h3"',
    }
  }

  /******  IMPORTERS   *******/

  /******  EXPORTERS   *******/

  getWireRdata() {
    const targetBytes = this.wirePackDomain(this.get('target name'));
    const paramsBytes = svcParamsToWire(this.get('params'));
    const result = new Uint8Array(2 + targetBytes.length + paramsBytes.length);
    new DataView(result.buffer).setUint16(0, this.get('priority'));
    result.set(targetBytes, 2);
    result.set(paramsBytes, 2 + targetBytes.length);
    return result
  }
}

// RFC 6698 §2.1.3: matching types 1 and 2 are SHA-256 and SHA-512 digests.
const DIGEST_BYTES = { 1: 32, 2: 64 };

class TLSA extends RR {
  static typeName = 'TLSA'
  static typeId = 52
  static RFCs = [6698, 7671]
  static rdataFields = [
    ['certificate usage', 'u8'],
    ['selector', 'u8'],
    ['matching type', 'u8'],
    ['certificate association data', 'hex'],
  ]
  static tags = ['security']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setCertificateUsage(val) {
    if (!this.getCertificateUsageOptions().has(val)) this.throwHelp(`TLSA: certificate usage invalid`);

    this.set('certificate usage', val);
  }

  getCertificateUsageOptions() {
    return new Map([
      [0, 'CA certificate'],
      [1, 'an end entity certificate'],
      [2, 'the trust anchor'],
      [3, 'domain-issued certificate'],
    ])
  }

  setSelector(val) {
    if (!this.getSelectorOptions().has(val)) this.throwHelp(`TLSA: selector invalid`);

    this.set('selector', val);
  }

  getSelectorOptions() {
    return new Map([
      [0, 'Full certificate'],
      [1, 'SubjectPublicKeyInfo'],
    ])
  }

  setMatchingType(val) {
    if (!this.getMatchingTypeOptions().has(val)) this.throwHelp(`TLSA: matching type`);
    const data = this.get('certificate association data');
    if (data !== undefined) this.isHexDigest('certificate association data', data, DIGEST_BYTES[val]);
    this.set('matching type', val);
  }

  getMatchingTypeOptions() {
    return new Map([
      [0, 'Exact match'],
      [1, 'SHA-256 hash'],
      [2, 'SHA-512 hash'],
    ])
  }

  setCertificateAssociationData(val) {
    this.isHexDigest('certificate association data', val, DIGEST_BYTES[this.get('matching type')]);
    this.set('certificate association data', val);
  }

  getDescription() {
    return 'TLSA certificate association'
  }

  getCanonical() {
    return {
      owner: '_443._tcp.www.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'TLSA',
      'certificate usage': 3,
      selector: 1,
      'matching type': 1,
      'certificate association data': 'D2ABDE240D7CD3EE6B4B28C54DF034B97983A1D16E8A410E4561CB106618E971',
    }
  }

  /******  IMPORTERS   *******/

  fromTinydns({ tinyline }) {
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline);
    if (typeId != this.getTypeId()) this.throwHelp('TLSA fromTinydns, invalid n');

    const bytes = octalRdataToBytes(rdata);

    return new TLSA({
      owner,
      ttl,
      type: 'TLSA',
      'certificate usage': bytes[0],
      selector: bytes[1],
      'matching type': bytes[2],
      'certificate association data': bytesToHex(bytes.subarray(3)),
      timestamp,
      location,
    })
  }

  /******  EXPORTERS   *******/
  toTinydns() {
    return this.getTinydnsGeneric(
      UInt8toOctal(this.get('certificate usage')) +
        UInt8toOctal(this.get('selector')) +
        UInt8toOctal(this.get('matching type')) +
        packHex(this.get('certificate association data').replace(/[\s()]/g, '')),
    )
  }

  getWireRdata() {
    const cadBytes = hexToBytes(this.get('certificate association data').replace(/[\s()]/g, ''));
    const bytes = new Uint8Array(3 + cadBytes.length);
    bytes[0] = this.get('certificate usage');
    bytes[1] = this.get('selector');
    bytes[2] = this.get('matching type');
    bytes.set(cadBytes, 3);
    return bytes
  }
}

class TSIG extends RR {
  static typeName = 'TSIG'
  static typeId = 250
  static RFCs = [2845, 8945]
  static rdataFields = ['algorithm name', 'time signed', 'fudge', 'mac', 'original id', 'error', 'other']
  static errorNames = {
    NOERROR: 0,
    BADSIG: 16,
    BADKEY: 17,
    BADTIME: 18,
    BADMODE: 19,
    BADNAME: 20,
    BADALG: 21,
    BADTRUNC: 22,
    BADCOOKIE: 23,
  }

  constructor(opts) {
    super(opts);
    if (opts === null) return
  }

  /****** Resource record specific setters   *******/

  getDescription() {
    return 'Transaction Signature'
  }

  getCanonical() {
    return {
      owner: 'test.example.',
      ttl: 0,
      class: 'ANY',
      type: 'TSIG',
      'algorithm name': 'hmac-sha256.',
      'time signed': 1620650000,
      fudge: 300,
      mac: '3q2+7w==',
      'original id': 12345,
      error: 0,
      other: '',
    }
  }

  setClass(t) {
    if (t !== 'ANY') this.throwHelp('TSIG: Class is required to be ANY');
    this.set('class', t);
  }

  setTtl(t) {
    if (t !== 0) this.throwHelp('TSIG: TTL is required to be 0');
    this.set('ttl', t);
  }

  setAlgorithmName(val) {
    if (!val) this.throwHelp(`TSIG: 'algorithm name' is required`);
    this.set('algorithm name', val);
  }

  setTimeSigned(val) {
    if (val === undefined) this.throwHelp(`TSIG: 'time signed' is required`);
    if (!Number.isInteger(val) || val < 0 || val >= 2 ** 48)
      this.throwHelp(`TSIG: 'time signed' must be a 48-bit integer`);
    this.set('time signed', val);
  }

  setFudge(val) {
    // 16-bit unsigned
    this.is16bitInt('TSIG', 'fudge', val);
    this.set('fudge', val);
  }

  setMac(val) {
    if (val) this.isBase64('TSIG', 'mac', val);
    this.set('mac', val ?? '');
  }

  setOriginalId(val) {
    this.is16bitInt('TSIG', 'original id', val);
    this.set('original id', val);
  }

  setError(val) {
    this.is16bitInt('TSIG', 'error', val);
    this.set('error', val);
  }

  setOther(val) {
    if (val) this.isBase64('TSIG', 'other', val);
    this.set('other', val ?? '');
  }

  /******  IMPORTERS   *******/

  fromBind({ owner, ttl, class: cls, rdata }) {
    // BIND presentation: alg time fudge mac-size mac original-id error other-len other.
    // MAC and Other are base64 that may span tokens, sized by the count before them.
    const words = rdata.map((t) => t.text);
    let i = 0;
    const next = (field) => {
      if (i === words.length) throw new Error(`TSIG: missing rdata: ${field}`)
      return words[i++]
    };
    const int = (field) => {
      const word = next(field);
      if (!/^\d+$/.test(word)) throw new Error(`TSIG: ${field} must be an integer: ${word}`)
      return parseInt(word, 10)
    };
    const base64 = (field, size) => {
      // padded base64 is exactly 4 characters per started 3 bytes
      const want = 4 * Math.ceil(size / 3);
      let b64 = '';
      while (b64.length < want) b64 += next(field);
      const valid = b64.length === want && /^[A-Za-z0-9+/]*={0,2}$/.test(b64);
      if (!valid || base64ToBytes(b64).length !== size)
        throw new Error(`TSIG: ${field} is not ${size} bytes of base64`)
      return b64
    };

    const algorithmName = next('algorithm name');
    const timeSigned = int('time signed');
    const fudge = int('fudge');
    const mac = base64('mac', int('mac size'));
    const originalId = int('original id');
    const errorWord = next('error');
    const error =
      TSIG.errorNames[errorWord.toUpperCase()] ??
      (/^\d+$/.test(errorWord) ? parseInt(errorWord, 10) : undefined);
    if (error === undefined) throw new Error(`TSIG: error must be an rcode name or an integer: ${errorWord}`)
    const other = base64('other', int('other len'));
    if (i < words.length) throw new Error(`TSIG: unexpected rdata: ${words.slice(i).join(' ')}`)

    return new TSIG({
      owner,
      ttl,
      class: cls,
      type: 'TSIG',
      'algorithm name': algorithmName,
      'time signed': timeSigned,
      fudge,
      mac,
      'original id': originalId,
      error,
      other,
    })
  }

  fromTinydns({ tinyline }) {
    const [owner, _typeId, rdata, ttl, ts, loc] = tinyline.slice(1).split(':');

    const algUnpacked = unpackDomainName(rdata);
    const algBinaryLen = algUnpacked[2];

    const bytes = Uint8Array.from(octalToChar(rdata), (c) => c.charCodeAt(0));
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    const { timeSigned, fudge, mac, originalId, error, other } = unpackTail(bytes, dv, algBinaryLen);

    return new TSIG({
      owner: this.fullyQualify(owner),
      ttl: parseInt(ttl, 10),
      class: 'ANY',
      type: 'TSIG',
      'algorithm name': algUnpacked[0],
      'time signed': timeSigned,
      fudge,
      mac,
      'original id': originalId,
      error,
      other,
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  fromWire({ owner, cls, ttl, rdata }) {
    const { fqdn: algorithmName, end } = this.wireUnpackDomain(rdata, 0);
    const dv = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
    const { timeSigned, fudge, mac, originalId, error, other } = unpackTail(rdata, dv, end);
    return new TSIG({
      owner,
      ttl: 0,
      class: 'ANY',
      type: 'TSIG',
      'algorithm name': algorithmName,
      'time signed': timeSigned,
      fudge,
      mac,
      'original id': originalId,
      error,
      other,
    })
  }

  /******  EXPORTERS   *******/
  toBind(zone_opts) {
    const mac = this.get('mac');
    const other = this.get('other');
    return (
      [
        this.getPrefix(zone_opts),
        this.get('algorithm name'),
        this.get('time signed'),
        this.get('fudge'),
        base64ToBytes(mac).length,
        mac,
        this.get('original id'),
        this.get('error'),
        base64ToBytes(other).length,
        other,
      ]
        .filter((f) => f !== '')
        .join('\t') + '\n'
    )
  }

  getWireRdata() {
    const algWire = wirePackDomain(this.get('algorithm name'));
    const macBytes = base64ToBytes(this.get('mac'));
    const otherBytes = base64ToBytes(this.get('other'));

    const bytes = new Uint8Array(algWire.length + 6 + 2 + 2 + macBytes.length + 2 + 2 + 2 + otherBytes.length);
    const dv = new DataView(bytes.buffer, bytes.byteOffset);
    let pos = 0;

    bytes.set(algWire, pos);
    pos += algWire.length;
    // RFC 8945 §4.2: Time Signed is 48 bits.
    dv.setUint16(pos, Math.floor(this.get('time signed') / 2 ** 32));
    dv.setUint32(pos + 2, this.get('time signed') % 2 ** 32);
    pos += 6;
    dv.setUint16(pos, this.get('fudge'));
    pos += 2;
    dv.setUint16(pos, macBytes.length);
    pos += 2;
    bytes.set(macBytes, pos);
    pos += macBytes.length;
    dv.setUint16(pos, this.get('original id'));
    pos += 2;
    dv.setUint16(pos, this.get('error'));
    pos += 2;
    dv.setUint16(pos, otherBytes.length);
    pos += 2;
    bytes.set(otherBytes, pos);

    return bytes
  }

  toTinydns() {
    const time = this.get('time signed');
    return this.getTinydnsGeneric(
      packDomainName(this.get('algorithm name')) +
        UInt16toOctal(Math.floor(time / 2 ** 32)) +
        UInt32toOctal(time % 2 ** 32) +
        UInt16toOctal(this.get('fudge')) +
        UInt16toOctal(base64ToBytes(this.get('mac')).length) +
        base64toOctal(this.get('mac')) +
        UInt16toOctal(this.get('original id')) +
        UInt16toOctal(this.get('error')) +
        UInt16toOctal(base64ToBytes(this.get('other')).length) +
        base64toOctal(this.get('other')),
    )
  }
}

// RFC 8945 §4.2: the rdata after the algorithm name.
// The MAC and Other Len fields must account for every remaining byte.
function unpackTail(bytes, dv, pos) {
  const need = (n) => {
    if (pos + n > bytes.length) throw new Error(`TSIG: rdata is truncated at byte ${pos}`)
  };
  need(10);
  const timeSigned = dv.getUint16(pos) * 2 ** 32 + dv.getUint32(pos + 2);
  pos += 6;
  const fudge = dv.getUint16(pos);
  const macSize = dv.getUint16(pos + 2);
  pos += 4;
  need(macSize + 6);
  const mac = bytesToBase64(bytes.subarray(pos, pos + macSize));
  pos += macSize;
  const originalId = dv.getUint16(pos);
  const error = dv.getUint16(pos + 2);
  const otherLen = dv.getUint16(pos + 4);
  pos += 6;
  need(otherLen);
  const other = bytesToBase64(bytes.subarray(pos, pos + otherLen));
  if (pos + otherLen !== bytes.length)
    throw new Error(`TSIG: ${bytes.length - pos - otherLen} bytes after Other Data`)
  return { timeSigned, fudge, mac, originalId, error, other }
}

/**
 * An RR of unknown type (RFC 3597). The numeric type id lives on the instance
 * (type: 'TYPE731'), not the class, so UNKNOWN is not in index.js's classes
 * array / typeMap. Rdata is opaque: a lowercase hex string, '' for zero-length.
 *
 * - index.js exports classFor('TYPE731' | 'MX' | 731), which resolves to the
 *   implementing class and to UNKNOWN for resolvable types without one;
 *   setType canonicalizes such mnemonics ('AFSDB' -> 'TYPE18')
 * - UNKNOWN.fromRR(rr) converts any RR to its generic representation;
 *   unknown.toRR(A) converts back through the class's wire codec
 * - a known type written in generic form is converted to its class, as
 *   RFC 3597 §5 requires: RR.A.fromBind('e.example. 3600 IN A \# 4 0a000001')
 *   returns an A record with address 10.0.0.1
 * - generic rdata a known class cannot re-encode byte-identically is rejected
 *   rather than silently altered — including uppercase embedded names, whose
 *   case this library (which stores names lowercase) cannot preserve
 * - meta-types (OPT, TSIG, ...) are not blocked from the generic form, though
 *   RFC 3597 §2 says they should not travel this way
 * - MaraDNS export is 'RAW nnn' with unquoted \xNN escapes ('' when empty);
 *   tinydns and MaraDNS exports require class IN
 */
class UNKNOWN extends RR {
  static typeName = 'UNKNOWN'
  static typeId = undefined // per-instance, see getTypeId()
  static RFCs = [3597]
  static rdataFields = [['rdata', 'hex']]
  static tags = []

  constructor(opts) {
    if (opts !== null && opts?.type === undefined && opts?.typeId !== undefined)
      opts = { ...opts, type: `TYPE${opts.typeId}` };
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setType(t) {
    if (t === undefined) this.throwHelp(`UNKNOWN: type is required (TYPEnnn, a mnemonic, or a numeric id)`);
    // canonicalize to TYPEnnn, so classFor('AFSDB') -> UNKNOWN can consume 'AFSDB'
    this.set('type', `TYPE${typeNameToId(t)}`);
  }

  setRdata(val) {
    if (val === undefined || val === null)
      this.throwHelp(`UNKNOWN: rdata is required (a hex string, '' for zero-length)`);
    if (typeof val !== 'string' || /[^0-9a-fA-F]/.test(val) || val.length % 2 !== 0)
      this.throwHelp(`UNKNOWN: rdata must be an even-length hex string`);
    this.set('rdata', val.toLowerCase());
  }

  getTypeId() {
    const t = this.get('type');
    if (t === undefined) this.throwHelp(`UNKNOWN: type is not set`);
    return parseInt(t.slice(4), 10)
  }

  getDescription() {
    return 'Unknown Resource Record (RFC 3597)'
  }

  getCanonical() {
    return {
      owner: 'a.example.',
      ttl: 3600,
      class: 'CLASS32',
      type: 'TYPE731',
      rdata: 'abcdef012345',
    }
  }

  /******  IMPORTERS   *******/

  fromBind() {
    this.throwHelp(`UNKNOWN: rdata must use the RFC 3597 generic form: \\# <length> <hex>`);
  }

  fromTinydns({ tinyline }) {
    const { owner, typeId, rdata, ttl, timestamp, location } = this.parseTinydnsLine(tinyline);
    if (!/^\d+$/.test(typeId ?? '') || parseInt(typeId, 10) > 65535)
      this.throwHelp(`UNKNOWN: invalid tinydns type id: ${typeId}`);
    return new UNKNOWN({
      owner,
      ttl,
      timestamp,
      location,
      type: `TYPE${parseInt(typeId, 10)}`,
      rdata: bytesToHex(octalRdataToBytes(rdata ?? '')),
    })
  }

  fromWire({ owner, cls, ttl, rdata, typeId }) {
    return new UNKNOWN({
      owner,
      ttl,
      class: cls,
      type: `TYPE${typeId}`,
      rdata: bytesToHex(rdata),
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    return hexToBytes(this.get('rdata'))
  }

  toBind(zone_opts) {
    const hex = this.get('rdata');
    const len = hex.length / 2;
    return `${this.getPrefix(zone_opts)}\t\\# ${len}${len ? ' ' + hex : ''}\n`
  }

  /******  CONVERTERS   *******/

  // any RR instance -> its RFC 3597 generic representation
  static fromRR(rr) {
    return new UNKNOWN({
      owner: rr.get('owner'),
      ttl: rr.get('ttl'),
      class: rr.get('class'),
      timestamp: rr.get('timestamp'),
      location: rr.get('location'),
      type: `TYPE${rr.getTypeId()}`,
      rdata: bytesToHex(rr.getWireRdata()),
    })
  }

  // generic representation -> a concrete RR class instance
  toRR(RRClass) {
    if (RRClass.typeId !== undefined && RRClass.typeId !== this.getTypeId())
      this.throwHelp(`UNKNOWN: type id ${this.getTypeId()} does not match ${RRClass.typeName}`);
    const rdata = hexToBytes(this.get('rdata'));
    const rr = new RRClass(null).fromWire({
      owner: this.get('owner'),
      cls: this.get('class'),
      ttl: this.get('ttl'),
      rdata,
      typeId: this.getTypeId(),
    });
    assertWireRoundTrip(rr, rdata);
    return rr
  }
}

class URI extends RR {
  static typeName = 'URI'
  static typeId = 256
  static RFCs = [7553]
  static rdataFields = [
    ['priority', 'u16'],
    ['weight', 'u16'],
    ['target', 'qstr'],
  ]

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setPriority(val) {
    this.is16bitInt('URI', 'priority', val);

    this.set('priority', val);
  }

  setWeight(val) {
    this.is16bitInt('URI', 'weight', val);

    this.set('weight', val);
  }

  setTarget(val) {
    if (!val) this.throwHelp(`URI: target is required`);

    this.set('target', val);
  }

  /******  IMPORTERS   *******/
  fromTinydns({ tinyline }) {
    // URI via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [fqdn, n, rdata, ttl, ts, loc] = tinyline.slice(1).split(':');
    if (n != 256) this.throwHelp('URI fromTinydns, invalid n');

    return new URI({
      type: 'URI',
      owner: this.fullyQualify(fqdn),
      priority: octalToUInt16(rdata.slice(0, 8)),
      weight: octalToUInt16(rdata.slice(8, 16)),
      target: octalToChar(rdata.slice(16)),
      ttl: parseInt(ttl, 10),
      timestamp: ts,
      location: loc?.trim() ?? '',
    })
  }

  /******  MISC   *******/
  getDescription() {
    return 'URI'
  }

  getCanonical() {
    return {
      owner: 'www.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'URI',
      priority: 10,
      weight: 10,
      target: 'http://www.example.com/',
    }
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const target = new TextEncoder().encode(this.get('target'));
    const result = new Uint8Array(4 + target.length);
    const dv = new DataView(result.buffer);
    dv.setUint16(0, this.get('priority'));
    dv.setUint16(2, this.get('weight'));
    result.set(target, 4);
    return result
  }

  toTinydns() {
    const dataRe = new RegExp(/[\r\n\t:\\/]/, 'g');
    let rdata = '';

    for (const e of ['priority', 'weight']) {
      rdata += UInt16toOctal(this.get(e));
    }

    rdata += escapeOctal(dataRe, this.get('target'));
    return this.getTinydnsGeneric(rdata)
  }
}

const WELL_KNOWN_PORTS = {
  echo: 7,
  discard: 9,
  systat: 11,
  daytime: 13,
  netstat: 15,
  ftp_data: 20,
  ftp: 21,
  ssh: 22,
  telnet: 23,
  smtp: 25,
  time: 37,
  rlp: 39,
  nameserver: 42,
  nicname: 43,
  domain: 53,
  mtp: 57,
  bootps: 67,
  bootpc: 68,
  tftp: 69,
  gopher: 70,
  rje: 77,
  finger: 79,
  http: 80,
  link: 87,
  supdup: 95,
  hostnames: 101,
  iso_tsap: 102,
  csnet_ns: 105,
  pop_2: 109,
  pop3: 110,
  sunrpc: 111,
  auth: 113,
  sftp: 115,
  uucp_path: 117,
  nntp: 119,
  ntp: 123,
  netbios_ns: 137,
  netbios_dgm: 138,
  netbios_ssn: 139,
  imap: 143,
  sql_net: 150,
  snmp: 161,
  snmp_trap: 162,
  cmip_man: 163,
  cmip_agent: 164,
  xdmcp: 177,
  nextstep: 178,
  bgp: 179,
  prospero: 191,
  irc: 194,
  smux: 199,
  at_rtmp: 201,
  at_nbp: 202,
  at_echo: 204,
  at_zis: 206,
  qmtp: 209,
  z3950: 210,
  ipx: 213,
  imap3: 220,
  ulistproc: 372,
  https: 443,
  snpp: 444,
  microsoft_ds: 445,
  kpasswd: 464,
  urd: 465,
  saft: 487,
  isakmp: 500,
  exec: 512,
  biff: 512,
  login: 513,
  who: 513,
  cmd: 514,
  syslog: 514,
  printer: 515,
  talk: 517,
  ntalk: 518,
  route: 520,
  timed: 525,
  tempo: 526,
  courier: 530,
  netnews: 532,
  netwall: 533,
  uucp: 540,
  remotefs: 556,
  nntps: 563,
  ldap: 389,
};

class WKS extends RR {
  static typeName = 'WKS'
  static typeId = 11
  static RFCs = [883, 1035]
  static rdataFields = [
    ['address', 'ipv4'],
    ['protocol', 'u8'],
    ['bit map', 'list'],
  ]
  static tags = ['obsolete']

  constructor(opts) {
    super(opts);
  }

  /****** Resource record specific setters   *******/
  setAddress(val) {
    if (!val) this.throwHelp('WKS: address is required');
    if (!this.isIPv4(val)) this.throwHelp('WKS address must be IPv4');
    this.set('address', val);
  }

  setProtocol(val) {
    if (!val) this.throwHelp('WKS: protocol is required');
    const upper = typeof val === 'string' ? val.toUpperCase() : val;
    if (!['TCP', 'UDP', 6, 17].includes(upper)) this.throwHelp('WKS protocol must be TCP or UDP');
    this.set('protocol', upper);
  }

  setBitMap(val) {
    for (const entry of (val ?? '').trim().split(/\s+/).filter(Boolean)) {
      const port = portNumber(entry);
      if (port === undefined || port > 65535)
        this.throwHelp(`WKS: bit map entry must be a known service or a port 0-65535: ${entry}`);
    }
    this.set('bit map', val ?? '');
  }

  getDescription() {
    return 'Well Known Service'
  }

  getCanonical() {
    return {
      owner: 'host.example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'WKS',
      address: '192.0.2.1',
      protocol: 'TCP',
      'bit map': 'ftp smtp',
    }
  }

  /******  IMPORTERS   *******/

  fromWire({ owner, cls, ttl, rdata }) {
    const address = [...rdata.subarray(0, 4)].join('.');
    const protoNum = rdata[4];
    const protoMap = { 6: 'TCP', 17: 'UDP' };
    const protocol = protoMap[protoNum] ?? String(protoNum);
    const PORT_NAMES = Object.fromEntries(Object.entries(WELL_KNOWN_PORTS).map(([k, v]) => [v, k]));
    const bitmap = rdata.subarray(5);
    const ports = [];
    for (let i = 0; i < bitmap.length; i++) {
      for (let bit = 0; bit < 8; bit++) {
        if (bitmap[i] & (0x80 >> bit)) {
          const port = i * 8 + bit;
          ports.push(PORT_NAMES[port] ?? String(port));
        }
      }
    }
    return new WKS({
      owner,
      ttl,
      class: cls,
      type: 'WKS',
      address,
      protocol,
      'bit map': ports.join(' '),
    })
  }

  /******  EXPORTERS   *******/

  getProtocolNumber() {
    return { TCP: 6, UDP: 17, 6: 6, 17: 17 }[this.get('protocol')]
  }

  getPorts() {
    return this.get('bit map').trim().split(/\s+/).filter(Boolean).map(portNumber)
  }

  // csv2(5): "IP protocol port,port,...", at most 10 ports, none above 1023.
  toMaraDNS() {
    const ports = this.getPorts();
    if (ports.length === 0 || ports.length > 10 || ports.some((p) => p > 1023)) return this.toMaraGeneric()
    this.assertClassIN('MaraDNS');
    return `${this.get('owner')}\t+${this.get('ttl')}\tWKS\t${this.get('address')} ${this.getProtocolNumber()} ${ports.join(',')} ~\n`
  }

  getWireRdata() {
    const addrBytes = this.get('address').split('.').map(Number);
    const protoNum = this.getProtocolNumber();
    const portNums = this.getPorts();

    if (portNums.length === 0) return new Uint8Array([...addrBytes, protoNum])

    const maxPort = Math.max(...portNums);
    const bitmapLen = Math.floor(maxPort / 8) + 1;
    const bitmap = new Uint8Array(bitmapLen);
    for (const port of portNums) bitmap[Math.floor(port / 8)] |= 0x80 >> (port % 8);

    const result = new Uint8Array(5 + bitmapLen);
    result.set(addrBytes);
    result[4] = protoNum;
    result.set(bitmap, 5);
    return result
  }
}

function portNumber(entry) {
  return /^\d+$/.test(entry) ? Number(entry) : WELL_KNOWN_PORTS[entry.toLowerCase()]
}

const typeMap = {};
const classes = [
  A,
  AAAA,
  APL,
  CAA,
  CERT,
  CNAME,
  DHCID,
  DNAME,
  DNSKEY,
  DS,
  HINFO,
  HIP,
  HTTPS,
  IPSECKEY,
  KEY,
  KX,
  LOC,
  MX,
  NAPTR,
  NS,
  NSEC,
  NSEC3,
  NSEC3PARAM,
  NXT,
  OPENPGPKEY,
  PTR,
  RP,
  RRSIG,
  SIG,
  SMIMEA,
  SSHFP,
  SOA,
  SPF,
  SRV,
  SVCB,
  TLSA,
  TSIG,
  TXT,
  URI,
  WKS,
];

for (const c of classes) {
  const id = c.getTypeId();
  typeMap[id] = c.typeName;
  typeMap[c.typeName] = id;
}

registerRdataFormats(classes);

// UNKNOWN stays out of the classes array: its type id is per-instance and an
// undefined static typeId would poison typeMap.
const classByName = {};
for (const c of classes) classByName[c.typeName] = c;

// 'MX' | 'TYPE731' (RFC 3597 §5) | 731 -> RR class constructor.
// Resolvable types without an implemented class (e.g. AFSDB) resolve to
// UNKNOWN; unresolvable names throw.
function classFor(type) {
  return classByName[typeMap[typeNameToId(type)]] ?? UNKNOWN
}

exports.A = A;
exports.AAAA = AAAA;
exports.APL = APL;
exports.CAA = CAA;
exports.CERT = CERT;
exports.CNAME = CNAME;
exports.DHCID = DHCID;
exports.DNAME = DNAME;
exports.DNSKEY = DNSKEY;
exports.DS = DS;
exports.HINFO = HINFO;
exports.HIP = HIP;
exports.HTTPS = HTTPS;
exports.IPSECKEY = IPSECKEY;
exports.KEY = KEY;
exports.KX = KX;
exports.LOC = LOC;
exports.MX = MX;
exports.NAPTR = NAPTR;
exports.NS = NS;
exports.NSEC = NSEC;
exports.NSEC3 = NSEC3;
exports.NSEC3PARAM = NSEC3PARAM;
exports.NXT = NXT;
exports.OPENPGPKEY = OPENPGPKEY;
exports.PTR = PTR;
exports.RP = RP;
exports.RRSIG = RRSIG;
exports.SIG = SIG;
exports.SMIMEA = SMIMEA;
exports.SOA = SOA;
exports.SPF = SPF;
exports.SRV = SRV;
exports.SSHFP = SSHFP;
exports.SVCB = SVCB;
exports.TLSA = TLSA;
exports.TSIG = TSIG;
exports.TXT = TXT;
exports.UNKNOWN = UNKNOWN;
exports.URI = URI;
exports.WKS = WKS;
exports.applyMap = applyMap;
exports.classFor = classFor;
exports.default = RR;
exports.getMap = getMap;
exports.typeMap = typeMap;
exports.unApplyMap = unApplyMap;
