
function escapeOctal (re, str) {
  let escaped = ''
  str.split(/(.{1})/g).map(c => {
    escaped += re.test(c) ? charToOctal(c) : c
  })
  return escaped
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

function packHex (str) {
  let r = ''
  for (var i = 0; i < str.length; i = i+2) {
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

module.exports = {
  escapeOctal,
  packDomainName,
  packHex,
  charToOctal,
  UInt8toOctal,
  UInt16toOctal,
}
