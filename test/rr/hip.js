import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import HIP from '../../rr/hip.js'

const publicKey =
  'AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwIXAqcOTiW7iHnQt5hwVAAAAA=='

const hipT =
  ':example.com:55:\\020\\002\\000O \\001\\000\\020{\\032t\\3376V9\\3149\\361\\325x\\003\\001\\000\\001\\267q\\312\\023nJ\\353\\134\\344C3\\305;=,\\023\\302"C\\205\\037\\307\\010\\274\\316)\\367\\342\\353W\\207\\265\\365l\\312\\323O\\202#\\254\\301\\011\\004\\335\\265k.\\304\\246\\326#/;P\\352\\011O\\002\\027\\002\\247\\016N%\\273\\210y\\320\\267\\230pT\\000\\000\\000:3600::\n'

const hipRvsT =
  ':host.example.com:55:\\020\\002\\000O \\001\\000\\020{\\032t\\3376V9\\3149\\361\\325x\\003\\001\\000\\001\\267q\\312\\023nJ\\353\\134\\344C3\\305;=,\\023\\302"C\\205\\037\\307\\010\\274\\316)\\367\\342\\353W\\207\\265\\365l\\312\\323O\\202#\\254\\301\\011\\004\\335\\265k.\\304\\246\\326#/;P\\352\\011O\\002\\027\\002\\247\\016N%\\273\\210y\\320\\267\\230pT\\000\\000\\000\\003rvs\\007example\\003com\\000:86400::\n'

const validRecords = [
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'HIP',
    'pk algorithm': 2,
    hit: '200100107B1A74DF365639CC39F1D578',
    'public key': publicKey,
    'rendezvous servers': '',
    testB: `example.com.\t3600\tIN\tHIP\t2\t200100107B1A74DF365639CC39F1D578\t${publicKey}\n`,
    testT: hipT,
    testW:
      '076578616d706c6503636f6d000037000100000e1000631002004f200100107b1a74df365639cc39f1d57803010001b771ca136e4aeb5ce44333c53b3d2c13c22243851fc708bcce29f7e2eb5787b5f56ccad34f8223acc10904ddb56b2ec4a6d6232f3b50ea094f021702a70e4e25bb8879d0b7987054000000',
  },
  {
    owner: 'host.example.com.',
    ttl: 86400,
    class: 'IN',
    type: 'HIP',
    'pk algorithm': 2,
    hit: '200100107B1A74DF365639CC39F1D578',
    'public key': publicKey,
    'rendezvous servers': 'rvs.example.com.',
    testB: `host.example.com.\t86400\tIN\tHIP\t2\t200100107B1A74DF365639CC39F1D578\t${publicKey}\trvs.example.com.\n`,
    testT: hipRvsT,
  },
]

const invalidRecords = [
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'HIP',
    'pk algorithm': undefined,
    hit: '200100107B1A74DF365639CC39F1D578',
    'public key': publicKey,
    'rendezvous servers': '',
    msg: /pk algorithm must be a 8-bit integer/,
  },
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'HIP',
    'pk algorithm': 2,
    hit: '',
    'public key': publicKey,
    'rendezvous servers': '',
    msg: /hit is required/,
  },
  {
    owner: 'example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'HIP',
    'pk algorithm': 2,
    hit: '200100107B1A74DF365639CC39F1D578',
    'public key': '',
    'rendezvous servers': '',
    msg: /public key is required/,
  },
]

describe('HIP record', function () {
  base.valid(HIP, validRecords)
  base.invalid(HIP, invalidRecords)

  base.getDescription(HIP)
  base.getRFCs(HIP, validRecords[0])
  base.getFields(HIP, ['pk algorithm', 'hit', 'public key', 'rendezvous servers'])
  base.getCanonical(HIP)
  base.getTypeId(HIP, 55)
  base.getTags(HIP)

  base.toBind(HIP, validRecords)
  base.toWire(HIP, validRecords)
  base.toTinydns(HIP, validRecords)

  base.fromBind(HIP, validRecords)
  base.fromTinydns(HIP, validRecords)
  base.fromWire(HIP, validRecords)

  test('fromBind rejects a public key split by whitespace (RFC 8005 §6)', () => {
    const bindline = `example.com.\t3600\tIN\tHIP\t2\t200100107B1A74DF365639CC39F1D578\t${publicKey.slice(0, 40)} ${publicKey.slice(40)} rvs.example.com.`
    assert.throws(() => HIP.fromBind(bindline), /rendezvous servers must be fully qualified/)
  })

  test('validates and lowercases each rendezvous server', () => {
    const hip = (servers) => new HIP({ ...validRecords[1], 'rendezvous servers': servers })
    assert.throws(
      () => hip('rvs.example.com. bad;name.example.'),
      /rendezvous servers has an unescaped delimiter/,
    )
    assert.equal(
      hip('RVS1.Example.com.   rvs2.example.com.').get('rendezvous servers'),
      'rvs1.example.com. rvs2.example.com.',
    )
  })

  test('validates the HIT and public key and their lengths (RFC 8005 §5)', () => {
    const hip = (fields) => new HIP({ ...validRecords[1], ...fields })
    assert.throws(() => hip({ hit: 'xyz' }), /hit must be hex octets/)
    assert.throws(() => hip({ hit: 'ab'.repeat(256) }), /hit must be <=255 bytes/)
    assert.throws(() => hip({ 'public key': 'not base64!' }), /public key must be a valid base64/)
    assert.equal(hip({ hit: 'abcd' }).get('hit'), 'ABCD')
  })

  test('rejects wire rdata whose HIT or key length overruns it', () => {
    const rdata = new HIP(validRecords[1]).getWireRdata()
    rdata[0] = 200
    assert.throws(
      () => new HIP(null).fromWire({ owner: 'x.', cls: 'IN', ttl: 60, rdata }),
      /overrun the rdata/,
    )
  })
})
