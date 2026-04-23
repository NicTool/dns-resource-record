import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import SSHFP from '../../rr/sshfp.js'

const common = { type: 'SSHFP', ttl: 86400, class: 'IN' }

const validRecords = [
  {
    ...common,
    owner: 'mail.example.com.',
    algorithm: 1,
    fptype: 1,
    fingerprint: 'ed8c6e16fdae4f633eee6a7b8f64fdd356bbb32841d535565d777014c9ea4c26',
    testB:
      'mail.example.com.\t86400\tIN\tSSHFP\t1\t1\ted8c6e16fdae4f633eee6a7b8f64fdd356bbb32841d535565d777014c9ea4c26\n',
    testT:
      ':mail.example.com:44:\\001\\001\\355\\214\\156\\026\\375\\256\\117\\143\\076\\356\\152\\173\\217\\144\\375\\323\\126\\273\\263\\050\\101\\325\\065\\126\\135\\167\\160\\024\\311\\352\\114\\046:86400::\n',
  },
  {
    ...common,
    owner: 'jails.example.com.',
    algorithm: 1,
    fptype: 1,
    fingerprint: '684981f1b57cc6b05bb2a5a7fd51a9114fef064d',
    testB: 'jails.example.com.\t86400\tIN\tSSHFP\t1\t1\t684981f1b57cc6b05bb2a5a7fd51a9114fef064d\n',
    testT:
      ':jails.example.com:44:\\001\\001\\150\\111\\201\\361\\265\\174\\306\\260\\133\\262\\245\\247\\375\\121\\251\\021\\117\\357\\006\\115:86400::\n',
  },
  {
    ...common,
    owner: 'jails.example.com.',
    algorithm: 3,
    fptype: 2,
    fingerprint: '81f9dbc4c009a1297336d69fcc2264f2a28417b781dafdd9c1ef7ff256066a35',
    testB:
      'jails.example.com.\t86400\tIN\tSSHFP\t3\t2\t81f9dbc4c009a1297336d69fcc2264f2a28417b781dafdd9c1ef7ff256066a35\n',
  },
  {
    ...common,
    owner: 'jails.example.com.',
    algorithm: 1,
    fptype: 2,
    fingerprint: 'ed8c6e16fdae4f633eee6a7b8f64fdd356bbb32841d535565d777014c9ea4c26',
    testB:
      'jails.example.com.\t86400\tIN\tSSHFP\t1\t2\ted8c6e16fdae4f633eee6a7b8f64fdd356bbb32841d535565d777014c9ea4c26\n',
  },
  {
    owner: 'ssh.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'SSHFP',
    algorithm: 1,
    fptype: 1,
    fingerprint: '546f3801f4159f81643666d97a9f73587000d60d',
    testB: 'ssh.nictool.tnpi.net.\t3600\tIN\tSSHFP\t1\t1\t546f3801f4159f81643666d97a9f73587000d60d\n',
    testT:
      ':ssh.nictool.tnpi.net:44:\\001\\001\\124\\157\\070\\001\\364\\025\\237\\201\\144\\066\\146\\331\\172\\237\\163\\130\\160\\000\\326\\015:3600::\n',
    testW:
      '03737368076e6963746f6f6c04746e7069036e657400002c000100000e1000160101546f3801f4159f81643666d97a9f73587000d60d',
  },
  {
    owner: 'ssh.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'SSHFP',
    algorithm: 3,
    fptype: 2,
    fingerprint: 'b0e5a9735d49246603d646b97607755e13583688b58a18357a700f7223644f77',
    testB:
      'ssh.nictool.tnpi.net.\t3600\tIN\tSSHFP\t3\t2\tb0e5a9735d49246603d646b97607755e13583688b58a18357a700f7223644f77\n',
    testT:
      ':ssh.nictool.tnpi.net:44:\\003\\002\\260\\345\\251\\163\\135\\111\\044\\146\\003\\326\\106\\271\\166\\007\\165\\136\\023\\130\\066\\210\\265\\212\\030\\065\\172\\160\\017\\162\\043\\144\\117\\167:3600::\n',
    testW:
      '03737368076e6963746f6f6c04746e7069036e657400002c000100000e1000220302b0e5a9735d49246603d646b97607755e13583688b58a18357a700f7223644f77',
  },
  {
    owner: 'ssh.nictool.tnpi.net.',
    ttl: 3600,
    class: 'IN',
    type: 'SSHFP',
    algorithm: 4,
    fptype: 2,
    fingerprint: '11e9a933f7608246f4142646f903745213583688b58a18357a700f7223644f77',
    testB:
      'ssh.nictool.tnpi.net.\t3600\tIN\tSSHFP\t4\t2\t11e9a933f7608246f4142646f903745213583688b58a18357a700f7223644f77\n',
    testT:
      ':ssh.nictool.tnpi.net:44:\\004\\002\\021\\351\\251\\063\\367\\140\\202\\106\\364\\024\\046\\106\\371\\003\\164\\122\\023\\130\\066\\210\\265\\212\\030\\065\\172\\160\\017\\162\\043\\144\\117\\167:3600::\n',
    testW:
      '03737368076e6963746f6f6c04746e7069036e657400002c000100000e100022040211e9a933f7608246f4142646f903745213583688b58a18357a700f7223644f77',
  },
]

const invalidRecords = [
  {
    ...common,
    owner: 'mail.example.com.',
    algorithm: 256,
    fptype: 1,
    fingerprint: 'ed8c6e16fdae4f633eee6a7b8f64fdd356bbb32841d535565d777014c9ea4c26',
    msg: /SSHFP algorithm must be a 8-bit integer/i,
  },
  {
    ...common,
    owner: 'mail.example.com.',
    algorithm: 1,
    fptype: 999,
    fingerprint: 'ed8c6e16fdae4f633eee6a7b8f64fdd356bbb32841d535565d777014c9ea4c26',
    msg: /SSHFP fptype must be a 8-bit integer/i,
  },
]

describe('SSHFP record', function () {
  base.valid(SSHFP, validRecords)
  base.invalid(SSHFP, invalidRecords)

  it('getAlgorithmOptions returns a Map of algorithm options', function () {
    const opts = new SSHFP(null).getAlgorithmOptions()
    assert.ok(opts instanceof Map)
    assert.equal(opts.get(1), 'RSA')
    assert.equal(opts.get(4), 'Ed25519')
  })

  it('getFptypeOptions returns a Map of fingerprint type options', function () {
    const opts = new SSHFP(null).getFptypeOptions()
    assert.ok(opts instanceof Map)
    assert.equal(opts.get(1), 'SHA-1')
    assert.equal(opts.get(2), 'SHA-256')
  })

  base.getDescription(SSHFP)
  base.getRFCs(SSHFP, validRecords[0])
  base.getFields(SSHFP, ['algorithm', 'fptype', 'fingerprint'])
  base.getCanonical(SSHFP)
  base.getTypeId(SSHFP, 44)
  base.getTags(SSHFP)

  base.toBind(SSHFP, validRecords)
  base.toWire(SSHFP, validRecords)
  base.toTinydns(SSHFP, validRecords)

  base.fromBind(SSHFP, validRecords)
  base.fromTinydns(SSHFP, validRecords)
})

  base.fromWire(SSHFP, validRecords)
