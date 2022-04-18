
import * as base from './base.js'

import KEY from '../rr/key.js'

const validRecords = [
  // {
  //   owner    : 'example.com.',
  //   ttl      : 3600,
  //   class    : 'IN',
  //   type     : 'KEY',
  //   flags    : 256,
  //   protocol : 3,
  //   algorithm: 5,
  //   publickey: `( AQPSKmynfzW4kyBv015MUG2DeIQ3 Cbl+BBZH4b/0PY1kxkmvHjcZc8no kfzj31GajIQKY+5CptLr3buXA10h WqTkF7H6RfoRqXQeogmMHfpftf6z Mv1LyBUgia7za6ZEzOJBOztyvhjL 742iU/TpPSEDhm2SNKLijfUppn1U aNvv4w== )`,
  //   testB    : '',
  //   // testT    : '',
  // },
]

const invalidRecords = [
]

describe('KEY record', function () {
  base.valid(KEY, validRecords)
  base.invalid(KEY, invalidRecords, { ttl: 3600 })

  base.getDescription(KEY)
  base.getRFCs(KEY, validRecords[0])
  base.getFields(KEY, [ 'flags', 'protocol', 'algorithm', 'publickey' ])
  base.getTypeId(KEY, 25)

  base.toBind(KEY, validRecords)
  // base.toTinydns(KEY, validRecords)

  base.fromBind(KEY, validRecords)
  // base.fromTinydns(KEY, validRecords)
})
