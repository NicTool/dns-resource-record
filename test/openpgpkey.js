import { describe } from 'node:test'
import * as base from './base.js'

import OPENPGPKEY from '../rr/openpgpkey.js'

const publicKey =
  'AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwIXAqcOTiW7iHnQt5hwVAAAAA=='

const validRecords = [
  {
    owner: 'matt.example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'OPENPGPKEY',
    'public key': publicKey,
    testB: `matt.example.com.\t3600\tIN\tOPENPGPKEY\t${publicKey}\n`,
    testT:
      ':matt.example.com:61:\\003\\001\\000\\001\\267q\\312\\023nJ\\353\\134\\344C3\\305\\073\\075\\054\\023\\302\\042C\\205\\037\\307\\010\\274\\316\\051\\367\\342\\353W\\207\\265\\365l\\312\\323O\\202\\043\\254\\301\\011\\004\\335\\265k.\\304\\246\\326\\043\\057\\073P\\352\\011O\\002\\027\\002\\247\\016N\\045\\273\\210y\\320\\267\\230pT\\000\\000\\000:3600::\n',
    testW:
      '046d617474076578616d706c6503636f6d00003d000100000e10004f03010001b771ca136e4aeb5ce44333c53b3d2c13c22243851fc708bcce29f7e2eb5787b5f56ccad34f8223acc10904ddb56b2ec4a6d6232f3b50ea094f021702a70e4e25bb8879d0b7987054000000',
  },
]

const invalidRecords = [
  {
    owner: 'matt.example.com.',
    ttl: 3600,
    class: 'IN',
    type: 'OPENPGPKEY',
    'public key': 'not-real-key-\u{1F600}',
    msg: /Latin-1/i,
  },
]

describe('OPENPGPKEY record', function () {
  base.valid(OPENPGPKEY, validRecords)
  base.invalid(OPENPGPKEY, invalidRecords, { ttl: 3600 })

  base.getDescription(OPENPGPKEY)
  base.getRFCs(OPENPGPKEY)
  base.getFields(OPENPGPKEY, ['public key'])
  base.getCanonical(OPENPGPKEY)
  base.getTypeId(OPENPGPKEY, 61)
  base.getTags(OPENPGPKEY)

  base.toBind(OPENPGPKEY, validRecords)
  base.toWire(OPENPGPKEY, validRecords)
  base.toTinydns(OPENPGPKEY, validRecords)

  base.fromBind(OPENPGPKEY, validRecords)
  base.fromTinydns(OPENPGPKEY, validRecords)
})
