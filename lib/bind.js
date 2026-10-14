import { hexToBytes, typeIdToName, typeNameToId } from './binary.js'
import { presentationBytes } from './name.js'
import { NUMERIC_FORMATS } from './nictool.js'
import { assertWireRoundTrip } from './wire.js'

// RFC 1035 §5.1 master-file lexer. Escapes stay in token text because their
// meaning depends on the field: in a name, `\.` is a dot inside a label.
// `"`, `(` and `)` delimit tokens even without whitespace, as in BIND. A token
// that touches the one before it is marked `adjoins`, so SVCB's key="value"
// survives as one parameter.
export function tokenize(line) {
  const tokens = []
  let token = null
  let depth = 0
  let separated = true
  const start = (quoted) => {
    token = separated ? { text: '', quoted } : { text: '', quoted, adjoins: true }
    separated = false
  }
  const flush = () => {
    if (token) tokens.push(token)
    token = null
  }
  const separate = () => {
    flush()
    separated = true
  }

  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (c === '\\') {
      if (i + 1 === line.length) throw new Error('BIND: incomplete escape')
      if (!token) start(false)
      token.text += c + line[++i]
    } else if (c === '"') {
      flush()
      start(true)
      for (i++; line[i] !== '"'; i++) {
        if (i >= line.length) throw new Error('BIND: unterminated quoted string')
        if (line[i] === '\n') throw new Error('BIND: newline in quoted string')
        if (line[i] === '\\') {
          if (i + 1 === line.length) throw new Error('BIND: incomplete escape')
          token.text += line[i++]
        }
        token.text += line[i]
      }
      flush()
    } else if (c === ';') {
      separate()
      while (i + 1 < line.length && line[i + 1] !== '\n') i++
    } else if (c === '(' || c === ')') {
      separate()
      depth += c === '(' ? 1 : -1
      if (depth < 0) throw new Error('BIND: unbalanced parentheses')
    } else if (c === '\n' && depth === 0) {
      separate()
      if (/\S/.test(line.slice(i + 1))) throw new Error('BIND: text after end of record')
    } else if (/\s/.test(c)) {
      separate()
    } else {
      if (!token) start(false)
      token.text += c
    }
  }
  flush()
  if (depth !== 0) throw new Error('BIND: unbalanced parentheses')
  return tokens
}

export function parseBindLine(line, RRClasses) {
  const res = {
    class: 'IN',
    type: '',
    rdata: [],
  }

  const tokens = tokenize(line)
  if (tokens.length < 1) return null

  if (!/^\s/.test(line)) {
    res.owner = tokens.shift().text
  }

  while (tokens.length > 0) {
    const token = tokens[0].text.toUpperCase()

    if (RRClasses[token]) {
      res.class = tokens.shift().text.toUpperCase()
      continue
    }

    if (/^CLASS\d+$/.test(token)) {
      // RFC 3597 §5 unknown-class syntax; setClass validates the number
      res.class = tokens.shift().text.toUpperCase()
      continue
    }

    if (/^\d+$/.test(token)) {
      res.ttl = parseInt(tokens.shift().text, 10)
      continue
    }

    res.type = tokens.shift().text.toUpperCase()
    break
  }

  res.rdata = tokens

  return res
}

// RFC 1035 §5.1: \DDD is an octet, \X is X. Octets must form UTF-8
export function decodeCharString(text) {
  let bytes
  try {
    bytes = presentationBytes(text)
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
export function escapeCharString(str) {
  return Array.from(String(str), (c) => {
    if (c === '"' || c === '\\') return `\\${c}`
    const code = c.codePointAt(0)
    return code < 0x20 || code === 0x7f ? `\\${String(code).padStart(3, '0')}` : c
  }).join('')
}

// A list field is the rest of the rdata, kept in presentation form for the
// RR's own setter to parse: type bit maps, APL items, SVCB params.
const listTypes = new Set(['list', 'svcparams'])

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
  const { hex } = parseGenericRdata(parsed.rdata.map((t) => t.text))
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

// UNKNOWN has no static typeId and accepts any TYPEnnn.
export function assertType(type, RRClass) {
  if (RRClass.typeId === undefined || type === RRClass.typeName) return
  if (!type) throw new Error(`expected ${RRClass.typeName}, got no type`)
  const typeNN = type.match(/^TYPE(\d+)$/)
  if (typeNN !== null && Number(typeNN[1]) === RRClass.typeId) return
  throw new Error(`expected ${RRClass.typeName}, got ${type}`)
}

export function fromBind(rrInstance, opts) {
  const { owner, ttl, class: cls, rdata } = opts
  const typeName = rrInstance.constructor.typeName
  const result = {
    owner,
    ttl,
    class: cls,
    type: typeName,
  }

  const fields = rrInstance.getFields('rdata')
  const rdataDefs = rrInstance.constructor.rdataFields ?? []
  const opaqueTypes = new Set(['str', 'hex', 'base64'])
  const lastType = fieldTypeOf(rdataDefs.at(-1))
  const lastIsList = listTypes.has(lastType)

  const required = lastIsList ? fields.length - 1 : fields.length
  if (rdata.length < required)
    throw new Error(`${typeName}: missing rdata: ${fields.slice(rdata.length).join(', ')}`)
  const lastIsVariadic = opaqueTypes.has(lastType) || lastType === 'charstrs' || lastIsList
  if (rdata.length > fields.length && !lastIsVariadic)
    throw new Error(
      `${typeName}: unexpected rdata: ${rdata
        .slice(fields.length)
        .map((t) => t.text)
        .join(' ')}`,
    )
  for (let i = 0; i < fields.length; i++) {
    const isLastField = i === fields.length - 1

    // RFC 1035 §5.1: opaque rdata (hex digests, base64 keys) may be split across
    // whitespace and parenthesized continuations; rejoin it into one value.
    if (isLastField && opaqueTypes.has(fieldTypeOf(rdataDefs[i]))) {
      result[fields[i]] = rdata
        .slice(i)
        .map((t) => t.text)
        .join('')
      break
    }

    if (isLastField && lastIsList) {
      result[fields[i]] = joinList(rdata.slice(i))
      break
    }

    // RFC 1035 §3.3.14: TXT keeps its character-string boundaries.
    if (isLastField && fieldTypeOf(rdataDefs[i]) === 'charstrs') {
      const strings = rdata.slice(i).map((t) => decodeCharString(t.text))
      result[fields[i]] = strings.length > 1 ? strings : strings[0]
      break
    }

    let val = rdata[i]?.text
    if (rrInstance.isQuotedField(fields[i])) {
      val = val === undefined ? undefined : decodeCharString(val)
    } else if (NUMERIC_FORMATS.has(fieldTypeOf(rdataDefs[i])) && /^\d+$/.test(val)) {
      val = parseInt(val, 10)
    }
    result[fields[i]] = val
  }

  return new rrInstance.constructor(result)
}

export function toBind(rrInstance, zone_opts) {
  const rdata = (rrInstance.constructor.rdataFields ?? []).map((def) => {
    const f = Array.isArray(def) ? def[0] : def
    if (rrInstance.isFqdnField(f)) return rrInstance.getFQDN(f, zone_opts)
    if (rrInstance.isQuotedField(f)) return `"${escapeCharString(rrInstance.get(f))}"`
    // RFC 4034 §3.2: a type is presented as its mnemonic, or TYPEnnn (RFC 3597).
    if (fieldTypeOf(def) === 'rrtype') return typeIdToName(rrInstance.get(f))
    return rrInstance.get(f)
  })
  // an empty trailing list (no rendezvous servers, an empty non-terminal) has no token
  if (listTypes.has(fieldTypeOf(rrInstance.constructor.rdataFields?.at(-1))) && rdata.at(-1) === '')
    rdata.pop()
  return `${[rrInstance.getPrefix(zone_opts), ...rdata].join('\t')}\n`
}
