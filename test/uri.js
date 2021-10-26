
// const assert = require('assert')

const base = require('./base')

const URI = require('../rr/uri')

const validRecords = [
  {
    class   : 'IN',
    name    : 'www.example.com',
    type    : 'URI',
    target  : 'www2.example.com.',
    priority: 1,
    weight  : 0,
    ttl     : 3600,
    testR   : 'www.example.com\t3600\tIN\tURI\t1\t0\t"www2.example.com."\n',
    testT   : ':www.example.com:256:\\000\\001\\000\\000www2.example.com.:3600::\n',
  },
  {
    class   : 'IN',
    name    : '_http.github.dog',
    type    : 'URI',
    target  : 'http://github.com/dog',
    priority: 2,
    weight  : 100,
    ttl     : 3600,
    testR   : '_http.github.dog\t3600\tIN\tURI\t2\t100\t"http://github.com/dog"\n',
    testT   : ':_http.github.dog:256:\\000\\002\\000\\144http\\072\\057\\057github.com\\057dog:3600::\n',
  },
]

const invalidRecords = [

]

describe('URI record', function () {
  base.valid(URI, validRecords)
  base.invalid(URI, invalidRecords)

  base.toBind(URI, validRecords)
  base.toTinydns(URI, validRecords)
})
