import * as base from './base.js'

import SSHFP from '../rr/sshfp.js'

const common = { type: 'SSHFP', ttl: 86400, class: 'IN' }

const validRecords = [
  {
    ...common,
    owner: 'mail.example.com.',
    algorithm: 1,
    fptype: 1,
    fingerprint:
      'ed8c6e16fdae4f633eee6a7b8f64fdd356bbb32841d535565d777014c9ea4c26',
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
    testB:
      'jails.example.com.\t86400\tIN\tSSHFP\t1\t1\t684981f1b57cc6b05bb2a5a7fd51a9114fef064d\n',
    testT:
      ':jails.example.com:44:\\001\\001\\150\\111\\201\\361\\265\\174\\306\\260\\133\\262\\245\\247\\375\\121\\251\\021\\117\\357\\006\\115:86400::\n',
  },
  {
    ...common,
    owner: 'jails.example.com.',
    algorithm: 3,
    fptype: 2,
    fingerprint:
      '81f9dbc4c009a1297336d69fcc2264f2a28417b781dafdd9c1ef7ff256066a35',
    testB:
      'jails.example.com.\t86400\tIN\tSSHFP\t3\t2\t81f9dbc4c009a1297336d69fcc2264f2a28417b781dafdd9c1ef7ff256066a35\n',
  },
  {
    ...common,
    owner: 'jails.example.com.',
    algorithm: 1,
    fptype: 2,
    fingerprint:
      'ed8c6e16fdae4f633eee6a7b8f64fdd356bbb32841d535565d777014c9ea4c26',
    testB:
      'jails.example.com.\t86400\tIN\tSSHFP\t1\t2\ted8c6e16fdae4f633eee6a7b8f64fdd356bbb32841d535565d777014c9ea4c26\n',
  },
]

const invalidRecords = []

describe('SSHFP record', function () {
  base.valid(SSHFP, validRecords)
  base.invalid(SSHFP, invalidRecords)

  base.getDescription(SSHFP)
  base.getRFCs(SSHFP, validRecords[0])
  base.getFields(SSHFP, ['algorithm', 'fptype', 'fingerprint'])
  base.getTypeId(SSHFP, 44)

  base.toBind(SSHFP, validRecords)
  base.toTinydns(SSHFP, validRecords)

  base.fromBind(SSHFP, validRecords)
  base.fromTinydns(SSHFP, validRecords)
})
