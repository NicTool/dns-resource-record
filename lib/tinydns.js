
const sprintf = require('sprintf-js').sprintf

function escapeOct (re, str) {
  let escaped = ''
  str.match(/(.{1})/g).map(c => {
    escaped += re.test(c) ? sprintf('\\%03o', c.charCodeAt(0)) : c
    // console.log(`${c}`)
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
    packed += sprintf('\\%03o', len.readUInt8(0))

    packed += escapeOct(labelRegEx, label)
  })
  packed += '\\000' // terminates with a zero length label
  return packed
}

module.exports = {
  escapeOct,
  packDomainName,
}
