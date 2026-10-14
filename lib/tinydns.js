const octalRe = new RegExp(/\\(?:[1-7][0-7]{0,2}|[0-7]{2,3})/, 'g')

export function parseFields(tinyline, rdataCount) {
  const parts = tinyline.slice(1).split(':')
  const owner = parts[0]
  const rdata = parts.slice(1, 1 + rdataCount)
  const [ttl, timestamp, location] = parts.slice(1 + rdataCount)
  return { owner, rdata, ttl, timestamp, location: location?.trim() ?? '' }
}

export function parseGenericLine(tinyline) {
  // Generic form: :owner:typeId:rdata:ttl:timestamp:location
  const [owner, typeId, rdata, ttl, timestamp, location] = tinyline.slice(1).split(':')
  return { owner, typeId, rdata, ttl: parseInt(ttl, 10), timestamp, location: location?.trim() ?? '' }
}

// tinydns-data reads the file's bytes, so text between \NNN escapes is UTF-8.
export function octalRdataToBytes(rdata) {
  const enc = new TextEncoder()
  const bytes = []
  let last = 0
  for (const m of rdata.matchAll(octalRe)) {
    bytes.push(...enc.encode(rdata.slice(last, m.index)), parseInt(m[0].slice(1), 8) & 0xff)
    last = m.index + m[0].length
  }
  bytes.push(...enc.encode(rdata.slice(last)))
  return Uint8Array.from(bytes)
}

export function to(rrInstance) {
  // the class guard lives in getTinydnsPostamble(), which every line includes
  if (rrInstance.constructor.tinydnsType) {
    const fields = rrInstance.getFields('rdata')
    const rdata = fields
      .map((f) => {
        if (rrInstance.isFqdnField(f)) return rrInstance.getTinyFQDN(f)
        return rrInstance.get(f)
      })
      .join(':')
    return `${rrInstance.constructor.tinydnsType}${rrInstance.getTinyFQDN('owner')}:${rdata}:${rrInstance.getTinydnsPostamble()}\n`
  }
  return rrInstance.getTinydnsGeneric(bytesToTinydnsText(rrInstance.getWireRdata()))
}

export function fromGeneric(rrInstance, { tinyline }) {
  const fields = rrInstance.getFields('rdata')
  const { owner, rdata, ttl, timestamp, location } = parseFields(tinyline, fields.length)

  const result = {
    owner: rrInstance.fullyQualify(owner),
    type: rrInstance.constructor.typeName,
    ttl: parseInt(ttl, 10),
    timestamp: timestamp,
    location: location,
  }

  for (let i = 0; i < fields.length; i++) {
    const val = rdata[i]
    result[fields[i]] = rrInstance.isFqdnField(fields[i]) ? rrInstance.fullyQualify(val) : val
  }

  return new rrInstance.constructor(result)
}

// Printable ASCII stays readable; ':' and '\\' would end or escape a field.
export function bytesToTinydnsText(bytes) {
  let out = ''
  for (const b of bytes) {
    const c = String.fromCharCode(b)
    out += b >= 0x20 && b < 0x7f && c !== ':' && c !== '\\' ? c : `\\${b.toString(8).padStart(3, '0')}`
  }
  return out
}
