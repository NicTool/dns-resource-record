
import * as base from './base.js'

import DNSKEY from '../rr/dnskey.js'

const defaults = { class: 'IN', ttl: 3600, type: 'DNSKEY' }

const validRecords = [
  {
    ...defaults,
    owner    : 'example.com.',
    flags    : 256,
    protocol : 3,
    algorithm: 5,
    publickey: `( AQPSKmynfzW4kyBv015MUG2DeIQ3 Cbl+BBZH4b/0PY1kxkmvHjcZc8no kfzj31GajIQKY+5CptLr3buXA10h WqTkF7H6RfoRqXQeogmMHfpftf6z Mv1LyBUgia7za6ZEzOJBOztyvhjL 742iU/TpPSEDhm2SNKLijfUppn1U aNvv4w== )`,
    testB    : 'example.com.\t3600\tIN\tDNSKEY\t256\t3\t5\t( AQPSKmynfzW4kyBv015MUG2DeIQ3 Cbl+BBZH4b/0PY1kxkmvHjcZc8no kfzj31GajIQKY+5CptLr3buXA10h WqTkF7H6RfoRqXQeogmMHfpftf6z Mv1LyBUgia7za6ZEzOJBOztyvhjL 742iU/TpPSEDhm2SNKLijfUppn1U aNvv4w== )\n',
    testT    : ':example.com:48:\\001\\000\\003\\005( AQPSKmynfzW4kyBv015MUG2DeIQ3 Cbl+BBZH4b\\0570PY1kxkmvHjcZc8no kfzj31GajIQKY+5CptLr3buXA10h WqTkF7H6RfoRqXQeogmMHfpftf6z Mv1LyBUgia7za6ZEzOJBOztyvhjL 742iU\\057TpPSEDhm2SNKLijfUppn1U aNvv4w== ):3600::\n',
  },
]

const invalidRecords = [
  {
    ...defaults,
    owner    : 'test.example.com.',
    algorithm: 257,  // invalid
    msg      : /flags must be a 16-bit integer/,
  },
]

describe('DNSKEY record', function () {
  base.valid(DNSKEY, validRecords)
  base.invalid(DNSKEY, invalidRecords)

  base.getDescription(DNSKEY)
  base.getRFCs(DNSKEY, validRecords[0])
  base.getFields(DNSKEY, [ 'flags', 'protocol', 'algorithm', 'publickey' ])
  base.getTypeId(DNSKEY, 48)

  base.toBind(DNSKEY, validRecords)
  base.toTinydns(DNSKEY, validRecords)

  base.fromBind(DNSKEY, validRecords)
  base.fromTinydns(DNSKEY, validRecords)
})
