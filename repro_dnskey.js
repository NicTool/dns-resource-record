import DNSKEY from './rr/dnskey.js'
import { bytesToHex } from './lib/binary.js'

const dnskey = new DNSKEY({
  owner: 'example.com.',
  ttl: 3600,
  class: 'IN',
  type: 'DNSKEY',
  flags: 256,
  protocol: 3,
  algorithm: 5,
  publickey: 'AQPSKAsj8',
})

const wire = dnskey.toWire()
console.log('Wire hex:', bytesToHex(wire))

// If it's binary, 'AQPSKAsj8' should be converted from base64 to binary.
// 'A' in base64 is 000000. 'Q' is 010000. 'P' is 001111. 'S' is 010010.
// But if it's exported as a string, we will see 41 (A), 51 (Q), 50 (P), 53 (S) ...
if (wire.includes(0x41) && wire.includes(0x51)) {
  console.log('BUG DETECTED: DNSKEY wire format includes base64 string instead of binary!')
} else {
  console.log('No base64 string detected in wire format.')
}
