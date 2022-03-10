[![Module Tests](https://github.com/msimerson/dns-resource-record/actions/workflows/ci-test.yml/badge.svg)](https://github.com/msimerson/dns-resource-record/actions/workflows/ci-test.yml)
[![Coverage Status](https://coveralls.io/repos/github/msimerson/dns-resource-record/badge.svg?branch=master)](https://coveralls.io/github/msimerson/dns-resource-record?branch=master)

# dns-resource-record

DNS resource record parser, validator, exporter, and importer.


## SYNOPSIS

This module is used to:

- validate formatting, values, and RFC compliance of each RR
- import RRs from:
    - [x] BIND zone file lines
    - [x] tinydns entries
- export RRs to:
    - [x] [BIND](https://www.isc.org/bind/) [zone file format](https://bind9.readthedocs.io/en/latest/reference.html#zone-file)
    - [x] tinydns [data format](https://cr.yp.to/djbdns/tinydns-data.html)

This module intends to import and export wholly RFC compliant DNS resource records. If you discover a way to pass an invalid DNS record through this library, please [raise an issue](https://github.com/msimerson/dns-resource-record/issues).


## SUPPORTED RECORDS

Look in the `rr` directory for an up-to-date list. This module intends to include support for all current (ie, not officially deprecated) DNS RRs **and** all RRs that are in active use on the internet.

PRs are welcome, especially PRs with tests.

## USAGE

### SOA

```js
const RR = require('dns-resource-record')
try {
    console.log(new RR.SOA({
        name   : 'example.com',
        type   : 'SOA',
        mname  : 'matt.example.com.',
        rname  : 'ns1.example.com.',
        serial : 1,
        refresh: 7200,
        retry  : 3600,
        expire : 1209600,
        minimum: 3600,
        ttl    : 3600,
    }))
    SOA(12) [Map] {
      'class' => 'IN',
      'name' => 'example.com',
      'ttl' => 3600,
      'type' => 'SOA',
      'id' => 6,
      'minimum' => 3600,
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

Export to BIND format:

```js
const aAsJSON = {
    name   : 'test.example.com',
    type   : 'A',
    address: '192.0.2.127',
    ttl    : 3600,
}
console.log(new RR.A(aAsJSON).toBind())
test.example.com    3600    IN  A   192.0.2.127
```

Export to tinydns format:

```js
console.log(new RR.A(aAsJSON).toTinydns())
+test.example.com:192.0.2.127:3600::
```

### AAAA

```js
console.log(new RR.AAAA({
    name   : 'test.example.com',
    type   : 'AAAA',
    address: '2605:7900:20:a::4',
    ttl    : 3600,
}).toBind())
test.example.com    3600    IN  AAAA    2605:7900:20:a::4
```

### CAA

Convert a tinydns line to BIND:

```js
console.log(new RR.CAA({
    tinyline: ':ns1.example.com:257:\\000\\005issueletsencrypt.org:3600::'
}).toBind())
ns1.example.com 3600    IN  CAA 0   issue   "letsencrypt.org"
```


## TODO

See the file [TODO](TODO.md)
