export function parseBindLine(line, RRClasses) {
  const res = {
    class: 'IN',
    type: '',
    rdata: [],
  }

  // 1. Strip comments (not inside quotes)
  let cleanLine = ''
  let inQuote = false
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (c === '"') inQuote = !inQuote
    if (c === ';' && !inQuote) break
    cleanLine += c
  }
  cleanLine = cleanLine.trim()
  if (!cleanLine) return null

  // 2. Tokenize, respecting quoted strings
  const tokens = cleanLine.match(/(".*?"|\S+)/g) || []
  if (tokens.length < 1) return null

  // 3. Owner handling
  if (!/^\s/.test(line)) {
    res.owner = tokens.shift()
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
      const tokens = rdata.slice(i).map((s) => s.replace(/^"|"$/g, ''))
      // For `charstrs` (TXT), preserve multi-string boundaries (RFC 1035 §3.3.14).
      // For `qstr`/`qcharstr` (single character-string), join into one string.
      const fieldType = fieldTypeOf(rdataDefs[i])
      result[fields[i]] = fieldType === 'charstrs' && tokens.length > 1 ? tokens : tokens.join('')
      break
    }

    let val = rdata[i]
    if (rrInstance.isQuotedField(fields[i])) {
      val = val?.replace(/^"|"$/g, '')
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
