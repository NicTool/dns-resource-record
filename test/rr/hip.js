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

const valid = [
  {
    owner: 'example.com.',
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
    'pk algorithm': 2,
    hit: '200100107B1A74DF365639CC39F1D578',
    'public key': publicKey,
    'rendezvous servers': 'rvs.example.com.',
    testB: `host.example.com.\t86400\tIN\tHIP\t2\t200100107B1A74DF365639CC39F1D578\t${publicKey}\trvs.example.com.\n`,
    testT: hipRvsT,
  },
]

const invalid = [
  {
    owner: 'example.com.',
    'pk algorithm': undefined,
    hit: '200100107B1A74DF365639CC39F1D578',
    'public key': publicKey,
    'rendezvous servers': '',
    msg: /pk algorithm must be a 8-bit integer/,
  },
  {
    owner: 'example.com.',
    'pk algorithm': 2,
    hit: '',
    'public key': publicKey,
    'rendezvous servers': '',
    msg: /hit is required/,
  },
  {
    owner: 'example.com.',
    'pk algorithm': 2,
    hit: '200100107B1A74DF365639CC39F1D578',
    'public key': '',
    'rendezvous servers': '',
    msg: /public key is required/,
  },
  // RFC 8005 §5, §6
  ...[
    [{ hit: 'xyz' }, /hit must be hex octets/],
    [{ hit: 'ab'.repeat(256) }, /hit must be <=255 bytes/],
    [{ 'public key': 'not base64!' }, /public key must be a valid base64/],
    [
      { 'rendezvous servers': 'rvs.example.com. bad;name.example.' },
      /rendezvous servers has an unescaped delimiter/,
    ],
  ].map(([fields, msg]) => ({ ...valid[1], ...fields, msg })),
  {
    bindline: `example.com.\t3600\tIN\tHIP\t2\t200100107B1A74DF365639CC39F1D578\t${publicKey.slice(0, 40)} ${publicKey.slice(40)} rvs.example.com.`,
    msg: /rendezvous servers must be fully qualified/,
  },
]

describe('HIP record', function () {
  base.suite(HIP, {
    typeId: 55,
    fields: ['pk algorithm', 'hit', 'public key', 'rendezvous servers'],
    valid,
    invalid,
  })

  test('stores the HIT uppercase and rendezvous servers lowercase', () => {
    const r = new HIP({
      ...valid[1],
      hit: 'abcd',
      'rendezvous servers': 'RVS1.Example.com.   rvs2.example.com.',
    })
    assert.equal(r.get('hit'), 'ABCD')
    assert.equal(r.get('rendezvous servers'), 'rvs1.example.com. rvs2.example.com.')
  })

  test('rejects wire rdata whose HIT or key length overruns it', () => {
    const rdata = new HIP(valid[1]).getWireRdata()
    rdata[0] = 200
    assert.throws(
      () => new HIP(null).fromWire({ owner: 'x.', cls: 'IN', ttl: 60, rdata }),
      /overrun the rdata/,
    )
  })
})
