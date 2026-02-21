import * as base from './base.js'

import HIP from '../rr/hip.js'

const publicKey =
  'AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwIXAqcOTiW7iHnQt5hwVAAAAA=='

const hipT =
  ':example.com:55:\\020\\002\\000\\117\\040\\001\\000\\020\\173\\032\\164\\337\\066\\126\\071\\314\\071\\361\\325\\170\\003\\001\\000\\001\\267\\161\\312\\023\\156\\112\\353\\134\\344\\103\\063\\305\\073\\075\\054\\023\\302\\042\\103\\205\\037\\307\\010\\274\\316\\051\\367\\342\\353\\127\\207\\265\\365\\154\\312\\323\\117\\202\\043\\254\\301\\011\\004\\335\\265\\153\\056\\304\\246\\326\\043\\057\\073\\120\\352\\011\\117\\002\\027\\002\\247\\016\\116\\045\\273\\210\\171\\320\\267\\230\\160\\124\\000\\000\\000:3600::\n'

const hipRvsT =
  ':host.example.com:55:\\020\\002\\000\\117\\040\\001\\000\\020\\173\\032\\164\\337\\066\\126\\071\\314\\071\\361\\325\\170\\003\\001\\000\\001\\267\\161\\312\\023\\156\\112\\353\\134\\344\\103\\063\\305\\073\\075\\054\\023\\302\\042\\103\\205\\037\\307\\010\\274\\316\\051\\367\\342\\353\\127\\207\\265\\365\\154\\312\\323\\117\\202\\043\\254\\301\\011\\004\\335\\265\\153\\056\\304\\246\\326\\043\\057\\073\\120\\352\\011\\117\\002\\027\\002\\247\\016\\116\\045\\273\\210\\171\\320\\267\\230\\160\\124\\000\\000\\000\\003rvs\\007example\\003com\\000:86400::\n'

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
  base.toTinydns(HIP, validRecords)

  base.fromBind(HIP, validRecords)
})
