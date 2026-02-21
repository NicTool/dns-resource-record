import * as base from './base.js'

import HIP from '../rr/hip.js'

const publicKey =
  'AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwIXAqcOTiW7iHnQt5hwVAAAAA=='

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
    msg: /pk algorithm is required/,
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
  base.getTypeId(HIP, 55)

  base.toBind(HIP, validRecords)

  base.fromBind(HIP, validRecords)
})
