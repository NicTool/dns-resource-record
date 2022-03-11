
// const assert = require('assert')

const base = require('./base')

const DNSKEY = require('../rr/dnskey')

const validRecords = [
  {
    name     : 'example.com',
    class    : 'IN',
    ttl      : 3600,
    type     : 'DNSKEY',
    flags    : 256,
    protocol : 3,
    algorithm: 5,
    publickey: `( AQPSKmynfzW4kyBv015MUG2DeIQ3 Cbl+BBZH4b/0PY1kxkmvHjcZc8no kfzj31GajIQKY+5CptLr3buXA10h WqTkF7H6RfoRqXQeogmMHfpftf6z Mv1LyBUgia7za6ZEzOJBOztyvhjL 742iU/TpPSEDhm2SNKLijfUppn1U aNvv4w== )`,
    testB    : 'example.com\t3600\tIN\tDNSKEY\t256\t3\t5\t( AQPSKmynfzW4kyBv015MUG2DeIQ3 Cbl+BBZH4b/0PY1kxkmvHjcZc8no kfzj31GajIQKY+5CptLr3buXA10h WqTkF7H6RfoRqXQeogmMHfpftf6z Mv1LyBUgia7za6ZEzOJBOztyvhjL 742iU/TpPSEDhm2SNKLijfUppn1U aNvv4w== )\n',
    testT    : ':dnskey.example.com:33:\\000\\001\\000\\000\\003\\341\\004mail\\007example\\003com\\000:3600::\n',
  },
]

const invalidRecords = [
  // {
  //   name     : 'test.example.com',
  //   class    : 'IN',
  //   type     : 'DNSKEY',
  //   ttl      : 3600,
  //   algorithm: 6,  // invalid
  // },
]

describe('DNSKEY record', function () {
  base.valid(DNSKEY, validRecords)
  base.invalid(DNSKEY, invalidRecords)

  base.getDescription(DNSKEY)
  base.getRFCs(DNSKEY, validRecords[0])
  base.getFields(DNSKEY, [ 'flags', 'protocol', 'algorithm', 'publickey' ])
  base.getTypeId(DNSKEY, 48)

  base.toBind(DNSKEY, validRecords)
  // base.toTinydns(DNSKEY, validRecords)

  base.fromBind(DNSKEY, validRecords)
  // base.fromTinydns(DNSKEY, validRecords)
})