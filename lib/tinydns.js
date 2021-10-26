
const SPECIALCHARS = {
  '+': [ 'A' ],
  '-': [ undefined ],
  '%': [ 'location' ],
  '.': [ 'SOA', 'NS', 'A' ],
  '&': [ 'NS', 'A' ],
  '=': [ 'A', 'PTR' ],
  '@': [ 'MX', 'A' ],
  '#': [ 'comment' ],
  "'": [ 'TXT' ],
  '^': [ 'PTR' ],
  'C': [ 'CNAME' ],
  'Z': [ 'SOA' ],
  ':': [ 'generic' ],
  '3': [ 'AAAA' ],
  '6': [ 'AAAA', 'PTR' ],
  'S': [ 'SRV' ],
}

const octalRe = new RegExp(/\\(?:[1-7][0-7]{0,2}|[0-7]{2,3})/, 'g')

function escapeOctal (re, str) {
  let escaped = ''
  str.split(/(.{1})/g).map(c => {
    escaped += re.test(c) ? charToOctal(c) : c
  })
  return escaped
}

function octalToChar (str) {
  // relace instances of \NNN with ASCII
  return str.replace(octalRe, o => String.fromCharCode(parseInt(o.substring(1), 8)))
}

function octalToHex (str) {
  // relace instances of \NNN with Hex
  return str.replace(octalRe, o => {
    // parseInt(n, 8) -> from octal to decimal
    //  .toString(16) -> decimal to hex
    return parseInt(o.substring(1), 8).toString(16).padStart(2, 0)
  })
}

function octalToUInt8 (str) {
  const b = Buffer.alloc(1)
  b.writeUInt8(parseInt(str.substring(1,4), 8), 0)
  return b.readUInt8()
}

function octalToUInt16 (str) {
  const b = Buffer.alloc(2)
  b.writeUInt8(parseInt(str.substring(1,4), 8), 0)
  b.writeUInt8(parseInt(str.substring(5,8), 8), 1)
  return b.readUInt16BE()
}

function packDomainName (fqdn) {
  const labelRegEx = new RegExp(/[^A-Za-z0-9-.]/, 'g')

  // RFC 1035, 3.3 Standard RRs
  // The standard wire format for DNS names. (1 octet length + octets)
  let packed = ''
  fqdn.split('.').map(label => {
    if (label === undefined || !label.length) return

    const len = Buffer.alloc(1)
    len.writeUInt8(label.length)
    packed += UInt8toOctal(len.readUInt8(0))

    packed += escapeOctal(labelRegEx, label)
  })
  packed += '\\000' // terminates with a zero length label
  return packed
}

function unpackDomainName (fqdn) {

  fqdn = Buffer.from(octalToChar(fqdn.toString()))

  const labels = []
  let pos = 0
  let len
  while ((len = fqdn.readUInt8(pos))) {
    pos++
    labels.push(fqdn.slice(pos, pos + len).toString())
    pos = +(pos + len)
  }

  return labels.join('.')
}

function packHex (str) {
  let r = ''
  for (let i = 0; i < str.length; i = i+2) {
    // nibble off 2 hex bytes, encode to octal
    r += UInt8toOctal(parseInt(str.slice(i, i+2), 16))
  }
  return r
}

function UInt8toOctal (n) {
  if (n > 255) throw new Error('UInt8toOctal does not work on numbers > 255')

  return `\\${parseInt(n, 10).toString(8).padStart(3, 0)}`
}

function charToOctal (c) {
  if (typeof c === 'number') return UInt8toOctal(c)

  return UInt8toOctal(c.charCodeAt(0))
}

function UInt16toOctal (n) {
  let r = ''
  const pri = Buffer.alloc(2)
  pri.writeUInt16BE(n)
  r += UInt8toOctal(pri.readUInt8(0))
  r += UInt8toOctal(pri.readUInt8(1))
  return r
}

function UInt32toOctal (n) {
  let r = ''
  const pri = Buffer.alloc(4)
  pri.writeUInt32BE(n)
  for (let i = 0; i < 4; i++) {
    r += UInt8toOctal(pri.readUInt8(i))
  }
  return r
}

module.exports = {
  charToOctal,
  escapeOctal,
  octalToChar,
  octalToHex,
  octalToUInt8,
  octalToUInt16,
  packDomainName,
  unpackDomainName,
  packHex,
  SPECIALCHARS,
  UInt8toOctal,
  UInt16toOctal,
  UInt32toOctal,
}
