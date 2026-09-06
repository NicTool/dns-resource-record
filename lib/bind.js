// Copyright (c) 2026, The NicTool Contributors

import { hexToBytes, typeNameToId } from './binary.js'
import { assertWireRoundTrip } from './wire.js'

export function parseBindLine(line, RRClasses) {
  const res = {
    class: 'IN',
    type: '',
    rdata: [],
  }

  const tokens = []
  let token = ''
  let inQuote = false
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (c === '\\') {
      if (i + 1 === line.length) throw new Error('BIND: incomplete escape')
      token += c + line[++i]
      continue
    }
    if (c === '"') inQuote = !inQuote
    if (c === ';' && !inQuote) break
    if (/\s/.test(c) && !inQuote) {
      if (token) tokens.push(token)
      token = ''
    } else {
      token += c
    }
  }
  if (inQuote) throw new Error('BIND: unterminated quoted string')
  if (token) tokens.push(token)
  if (tokens.length < 1) return null

  // 3. Owner handling
  if (!/^\s/.test(line)) {
    res.owner = characterString(tokens.shift())
  }

  // 4. Extract TTL, Class, and Type
  while (tokens.length > 0) {
    const token = tokens[0].toUpperCase()

    if (RRClasses[token]) {
      res.class = tokens.shift().toUpperCase()
      continue
    }

    if (/^CLASS\d+$/.test(token)) {
      // RFC 3597 §5 unknown-class syntax; setClass validates the number
      res.class = tokens.shift().toUpperCase()
      continue
    }

    if (/^\d+$/.test(token)) {
      res.ttl = parseInt(tokens.shift(), 10)
      continue
    }

    // If it's not a Class or TTL, it must be the RR Type (A, MX, etc.)
    res.type = tokens.shift().toUpperCase()
    break
  }

  // 5. Remaining tokens are RDATA
  res.rdata = tokens

  return res
}

function fieldTypeOf(def) {
  return Array.isArray(def) ? def[1] : null
}

export function escapeBindName(name) {
  const encoder = new TextEncoder()
  return name.replace(/[\s;"\\()\u0000-\u001f\u007f]/gu, (char) =>
    Array.from(encoder.encode(char), (byte) => '\\' + String(byte).padStart(3, '0')).join(''),
  )
}

function characterString(token) {
  const text = token.replace(/^"|"$/g, '')
  const bytes = []
  const encoder = new TextEncoder()
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\\') {
      if (++i === text.length) throw new Error('BIND: incomplete character-string escape')
      if (/[0-9]/.test(text[i])) {
        const decimal = text.slice(i, i + 3)
        if (!/^[0-9]{3}$/.test(decimal) || Number(decimal) > 255)
          throw new Error('BIND: invalid decimal character-string escape')
        bytes.push(Number(decimal))
        i += 2
        continue
      }
    }
    const char = String.fromCodePoint(text.codePointAt(i))
    bytes.push(...encoder.encode(char))
    i += char.length - 1
  }
  // The string API represents UTF-8, not arbitrary binary octets.
  return new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes))
}

// RFC 3597 §5 generic rdata: '\# <length> <hex words>', parens permitted.
// Every word must contain an even number of hex digits, not just the whole.
export function parseGenericRdata(tokens) {
  const words = tokens.filter((w) => w !== '(' && w !== ')')
  if (words[0] !== '\\#') throw new Error(`RFC 3597: generic rdata must begin with \\#`)
  if (!/^\d+$/.test(words[1] ?? '') || parseInt(words[1], 10) > 65535)
    throw new Error(`RFC 3597: invalid rdata length: ${words[1]}`)
  const length = parseInt(words[1], 10)
  for (const w of words.slice(2)) {
    if (!/^[0-9a-fA-F]+$/.test(w) || w.length % 2 !== 0)
      throw new Error(`RFC 3597: each rdata word must be an even number of hex digits: ${w}`)
  }
  const hex = words.slice(2).join('').toLowerCase()
  if (hex.length !== length * 2)
    throw new Error(`RFC 3597: rdata length mismatch: declared ${length}, got ${hex.length / 2} bytes`)
  return { length, hex }
}

// An RR of known type in generic form MUST be processed as the known type
// (RFC 3597 §5), so the hex is decoded through the class's wire parser.
export function fromBind3597(rrInstance, parsed) {
  const { hex } = parseGenericRdata(parsed.rdata)
  const staticId = rrInstance.constructor.typeId
  const typeId = typeNameToId(parsed.type) // 'TYPE731', 'AFSDB', ...; garbage throws
  if (staticId !== undefined && typeId !== staticId)
    throw new Error(`${rrInstance.constructor.typeName}: ${parsed.type} does not match type id ${staticId}`)
  const rdata = hexToBytes(hex)
  const rr = rrInstance.fromWire({
    owner: parsed.owner,
    cls: parsed.class,
    ttl: parsed.ttl,
    rdata,
    typeId: typeId ?? staticId,
  })
  assertWireRoundTrip(rr, rdata)
  return rr
}

export function fromBind(rrInstance, opts) {
  const { owner, ttl, class: cls, rdata } = opts
  const result = {
    owner,
    ttl,
    class: cls,
    type: rrInstance.constructor.typeName,
  }

  const fields = rrInstance.getFields('rdata')
  const rdataDefs = rrInstance.constructor.rdataFields ?? []
  const opaqueTypes = new Set(['str', 'hex', 'base64'])
  for (let i = 0; i < fields.length; i++) {
    const isLastField = i === fields.length - 1

    // RFC 1035 §5.1: opaque rdata (hex digests, base64 keys) may be split across
    // whitespace and parenthesized continuations; rejoin it into one value.
    if (isLastField && opaqueTypes.has(fieldTypeOf(rdataDefs[i]))) {
      result[fields[i]] = rdata.slice(i).join('')
      break
    }

    if (isLastField && rrInstance.isQuotedField(fields[i])) {
      // Collect all remaining tokens for TXT/etc
      const tokens = rdata.slice(i).map(characterString)
      // For `charstrs` (TXT), preserve multi-string boundaries (RFC 1035 §3.3.14).
      // For `qstr`/`qcharstr` (single character-string), join into one string.
      const fieldType = fieldTypeOf(rdataDefs[i])
      result[fields[i]] = fieldType === 'charstrs' && tokens.length > 1 ? tokens : tokens.join('')
      break
    }

    let val = rdata[i]
    if (rrInstance.isQuotedField(fields[i])) {
      val = val === undefined ? undefined : characterString(val)
    } else if (/^\d+$/.test(val)) {
      val = parseInt(val, 10)
    }
    result[fields[i]] = val
  }

  return new rrInstance.constructor(result)
}

export function toBind(rrInstance, zone_opts) {
  const fields = rrInstance.getFields('rdata')
  const rdata = fields
    .map((f) => (rrInstance.isFqdnField(f) ? rrInstance.getFQDN(f, zone_opts) : rrInstance.getQuoted(f)))
    .join('\t')
  return `${rrInstance.getPrefix(zone_opts)}\t${rdata}\n`
}
