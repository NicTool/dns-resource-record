[![Module Tests](https://github.com/msimerson/dns-resource-record/actions/workflows/ci-test.yml/badge.svg)](https://github.com/msimerson/dns-resource-record/actions/workflows/ci-test.yml)
[![Coverage Status](https://coveralls.io/repos/github/msimerson/dns-resource-record/badge.svg?branch=master)](https://coveralls.io/github/msimerson/dns-resource-record?branch=master)

# dns-resource-record

DNS resource record parser, validator, exporter, and (soon) importer.


## SYNOPSIS

This module will be used by a web client UI and a server side DNS Resource Record validator to:

- validate formatting, values, and RFC compliance of each RR
- export RRs to BIND zone file format
- export RRs to tinydns file format
- import RRs from BIND zone file lines
- import RRs from tinydns entries

This module intends to import and export wholly RFC compliant DNS resourse records. If you discover a way to pass an invalid DNS record through this library, please [raise an issue](https://github.com/msimerson/dns-resource-record/issues).


## USAGE

### SOA

```js
const RR = require('dns-resource-record')
try {
    console.log(RR.SOA({
        name   : 'example.com',
        type   : 'SOA',
        mname  : 'matt.example.com.',
        rname  : 'ns1.example.com.',
        serial : 1,
        refresh: 7200,
        retry  : 3600,
        expire : 1209600,
        ttl    : 3600,
    }))
    SOA(10) [Map] {
      'class' => 'IN',
      'name' => 'example.com',
      'ttl' => 3600,
      'type' => 'SOA',
      'mname' => 'matt.example.com.',
      'rname' => 'ns1.example.com.',
      'serial' => 1,
      'refresh' => 7200,
      'retry' => 3600,
      'expire' => 1209600
    }
}
catch (e) {
    // invalid RRs will throw
    console.error(e)
}
```

---

### A

```js
console.log(RR.A({
    name   : 'test.example.com',
    type   : 'A',
    address: '127.0.0.127',
    ttl    : 3600,
}))
A(5) [Map] {
  'class' => 'IN',
  'name' => 'test.example.com',
  'ttl' => 3600,
  'type' => 'A',
  'address' => '127.0.0.127'
}
```

## TODO

See the file [TODO](TODO.md)
