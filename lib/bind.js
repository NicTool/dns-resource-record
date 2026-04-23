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

export function fromBind(rrInstance, opts) {
  const { owner, ttl, cls, rdata } = opts
  const result = {
    owner,
    ttl,
    class: cls,
    type: rrInstance.constructor.typeName,
  }

  const fields = rrInstance.getFields('rdata')
  for (let i = 0; i < fields.length; i++) {
    const isLastField = i === fields.length - 1
    if (isLastField && rrInstance.isQuotedField(fields[i])) {
      // Collect all remaining tokens for TXT/etc
      const val = rdata
        .slice(i)
        .map((s) => s.replace(/^"|"$/g, ''))
        .join('')
      result[fields[i]] = val
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
