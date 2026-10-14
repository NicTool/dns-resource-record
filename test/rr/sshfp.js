import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import * as base from '../base.js'

import SSHFP from '../../rr/sshfp.js'

const common = { ttl: 86400 }

const valid = [
  {
    ...common,
    owner: 'mail.example.com.',
    algorithm: 1,
    fptype: 2,
    fingerprint: 'ED8C6E16FDAE4F633EEE6A7B8F64FDD356BBB32841D535565D777014C9EA4C26',
    testB:
      'mail.example.com.\t86400\tIN\tSSHFP\t1\t2\tED8C6E16FDAE4F633EEE6A7B8F64FDD356BBB32841D535565D777014C9EA4C26\n',
    testT:
      ':mail.example.com:44:\\001\\002\\355\\214n\\026\\375\\256Oc>\\356j{\\217d\\375\\323V\\273\\263(A\\3255V]wp\\024\\311\\352L&:86400::\n',
  },
  {
    ...common,
    owner: 'jails.example.com.',
    algorithm: 1,
    fptype: 1,
    fingerprint: '684981F1B57CC6B05BB2A5A7FD51A9114FEF064D',
    testB: 'jails.example.com.\t86400\tIN\tSSHFP\t1\t1\t684981F1B57CC6B05BB2A5A7FD51A9114FEF064D\n',
    testT:
      ':jails.example.com:44:\\001\\001hI\\201\\361\\265|\\306\\260[\\262\\245\\247\\375Q\\251\\021O\\357\\006M:86400::\n',
  },
  {
    ...common,
    owner: 'jails.example.com.',
    algorithm: 3,
    fptype: 2,
    fingerprint: '81F9DBC4C009A1297336D69FCC2264F2A28417B781DAFDD9C1EF7FF256066A35',
    testB:
      'jails.example.com.\t86400\tIN\tSSHFP\t3\t2\t81F9DBC4C009A1297336D69FCC2264F2A28417B781DAFDD9C1EF7FF256066A35\n',
  },
  {
    ...common,
    owner: 'jails.example.com.',
    algorithm: 1,
    fptype: 2,
    fingerprint: 'ED8C6E16FDAE4F633EEE6A7B8F64FDD356BBB32841D535565D777014C9EA4C26',
    testB:
      'jails.example.com.\t86400\tIN\tSSHFP\t1\t2\tED8C6E16FDAE4F633EEE6A7B8F64FDD356BBB32841D535565D777014C9EA4C26\n',
  },
  {
    owner: 'ssh.nictool.tnpi.net.',
    algorithm: 1,
    fptype: 1,
    fingerprint: '546F3801F4159F81643666D97A9F73587000D60D',
    testB: 'ssh.nictool.tnpi.net.\t3600\tIN\tSSHFP\t1\t1\t546F3801F4159F81643666D97A9F73587000D60D\n',
    testT:
      ':ssh.nictool.tnpi.net:44:\\001\\001To8\\001\\364\\025\\237\\201d6f\\331z\\237sXp\\000\\326\\015:3600::\n',
    testW:
      '03737368076e6963746f6f6c04746e7069036e657400002c000100000e1000160101546f3801f4159f81643666d97a9f73587000d60d',
  },
  {
    owner: 'ssh.nictool.tnpi.net.',
    algorithm: 3,
    fptype: 2,
    fingerprint: 'B0E5A9735D49246603D646B97607755E13583688B58A18357A700F7223644F77',
    testB:
      'ssh.nictool.tnpi.net.\t3600\tIN\tSSHFP\t3\t2\tB0E5A9735D49246603D646B97607755E13583688B58A18357A700F7223644F77\n',
    testT:
      ':ssh.nictool.tnpi.net:44:\\003\\002\\260\\345\\251s]I$f\\003\\326F\\271v\\007u^\\023X6\\210\\265\\212\\0305zp\\017r#dOw:3600::\n',
    testW:
      '03737368076e6963746f6f6c04746e7069036e657400002c000100000e1000220302b0e5a9735d49246603d646b97607755e13583688b58a18357a700f7223644f77',
  },
  {
    owner: 'ssh.nictool.tnpi.net.',
    algorithm: 4,
    fptype: 2,
    fingerprint: '11E9A933F7608246F4142646F903745213583688B58A18357A700F7223644F77',
    testB:
      'ssh.nictool.tnpi.net.\t3600\tIN\tSSHFP\t4\t2\t11E9A933F7608246F4142646F903745213583688B58A18357A700F7223644F77\n',
    testT:
      ':ssh.nictool.tnpi.net:44:\\004\\002\\021\\351\\2513\\367`\\202F\\364\\024&F\\371\\003tR\\023X6\\210\\265\\212\\0305zp\\017r#dOw:3600::\n',
    testW:
      '03737368076e6963746f6f6c04746e7069036e657400002c000100000e100022040211e9a933f7608246f4142646f903745213583688b58a18357a700f7223644f77',
  },
]

const sshfp = (algorithm, fptype, msg) => ({
  ...common,
  owner: 'mail.example.com.',
  algorithm,
  fptype,
  fingerprint: 'ED8C6E16FDAE4F633EEE6A7B8F64FDD356BBB32841D535565D777014C9EA4C26',
  msg,
})
// 5 and 3 are in the u8 range but unassigned in the IANA SSHFP registries
const invalid = [
  sshfp(256, 1, /SSHFP: algorithm invalid/),
  sshfp(5, 1, /SSHFP: algorithm invalid/),
  sshfp(1, 999, /SSHFP: fptype invalid/),
  sshfp(1, 3, /SSHFP: fptype invalid/),
]

describe('SSHFP record', function () {
  base.suite(SSHFP, {
    typeId: 44,
    fields: ['algorithm', 'fptype', 'fingerprint'],
    valid,
    invalid,
  })

  it('lists algorithm and fingerprint type options', function () {
    const r = new SSHFP(null)
    assert.equal(r.getAlgorithmOptions().get(1), 'RSA')
    assert.equal(r.getAlgorithmOptions().get(4), 'Ed25519')
    assert.equal(r.getFptypeOptions().get(1), 'SHA-1')
    assert.equal(r.getFptypeOptions().get(2), 'SHA-256')
  })

  it('revalidates the fingerprint when the fptype changes', function () {
    const r = new SSHFP(new SSHFP(null).getCanonical())
    assert.throws(() => r.setFptype(2), /fingerprint must be 32 bytes/)
    assert.equal(r.get('fptype'), 1)
  })
})
