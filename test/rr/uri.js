import { describe } from 'node:test'

import * as base from '../base.js'

import URI from '../../rr/uri.js'

const valid = [
  {
    owner: 'www.example.com.',
    target: 'www2.example.com.',
    priority: 1,
    weight: 0,
    testB: 'www.example.com.\t3600\tIN\tURI\t1\t0\t"www2.example.com."\n',
    testT: ':www.example.com:256:\\000\\001\\000\\000www2.example.com.:3600::\n',
  },
  {
    owner: '_http.github.dog.',
    target: 'http://github.com/dog',
    priority: 2,
    weight: 100,
    testB: '_http.github.dog.\t3600\tIN\tURI\t2\t100\t"http://github.com/dog"\n',
    testT: ':_http.github.dog:256:\\000\\002\\000dhttp\\072//github.com/dog:3600::\n',
  },
  {
    owner: '_http._tcp.nictool.tnpi.net.',
    priority: 1,
    weight: 10,
    target: 'https://nictool.tnpi.net/',
    testB: '_http._tcp.nictool.tnpi.net.\t3600\tIN\tURI\t1\t10\t"https://nictool.tnpi.net/"\n',
    testT: ':_http._tcp.nictool.tnpi.net:256:\\000\\001\\000\\012https\\072//nictool.tnpi.net/:3600::\n',
    testW:
      '055f68747470045f746370076e6963746f6f6c04746e7069036e6574000100000100000e10001d0001000a68747470733a2f2f6e6963746f6f6c2e746e70692e6e65742f',
  },
  {
    owner: '_ftp._tcp.nictool.tnpi.net.',
    priority: 1,
    weight: 10,
    target: 'ftp://ftp.nictool.tnpi.net/',
    testB: '_ftp._tcp.nictool.tnpi.net.\t3600\tIN\tURI\t1\t10\t"ftp://ftp.nictool.tnpi.net/"\n',
    testT: ':_ftp._tcp.nictool.tnpi.net:256:\\000\\001\\000\\012ftp\\072//ftp.nictool.tnpi.net/:3600::\n',
    testW:
      '045f667470045f746370076e6963746f6f6c04746e7069036e6574000100000100000e10001f0001000a6674703a2f2f6674702e6e6963746f6f6c2e746e70692e6e65742f',
  },
]

const invalid = [
  {
    owner: 'www.example.com.',
    priority: 1,
    weight: 0,
    msg: /target is required/i,
  },
]

describe('URI record', function () {
  base.suite(URI, {
    typeId: 256,
    fields: ['priority', 'weight', 'target'],
    valid,
    invalid,
  })
})
