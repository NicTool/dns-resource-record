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

## Supported Records

This module intends to include support for all current (ie, not officially deprecated) DNS RRs **and** all RRs that are in active use on the internet.

PRs are welcome, especially PRs with tests.

| **RR**     | **toBind**       | **toTinydns**    | **fromBind**     |  **fromTinydns** |     getRFCs      |
|:---------: |:----------------:|:----------------:|:----------------:|:----------------:|:----------------:|
| **A**      |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **AAAA**   |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **CAA**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **CNAME**  |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **DNAME**  |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **DNSKEY** |                  |                  |                  |                  |                  |
| **DS**     |                  |                  |                  |                  |                  |
| **HINFO**  |:white_check_mark:|                  |                  |                  |:white_check_mark:|
|**IPSECKEY**|                  |                  |                  |                  |                  |
| **LOC**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **MX**     |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **NAPTR**  |:white_check_mark:|:white_check_mark:|:white_check_mark:|                  |:white_check_mark:|
| **NS**     |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **PTR**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **SMIMEA** |                  |                  |                  |                  |                  |
| **SOA**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **SPF**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **SRV**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **SSHFP**  |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **TXT**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **URI**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|

## TODO

- [x] Change all IPs to use [RFC example/doc](https://en.wikipedia.org/wiki/Reserved_IP_addresses) address space
- [x] change all domains to use reserved doc names
- [ ] import tests from nictool/server/t/12_records.t
- [x] add defaults for empty values like TTL?
- [ ] DNSSEC RRs, probably not: RRSIG, NSEC, NSEC3, NSEC3PARAM
- [ ] Additional RRs?: KX, CERT, DHCID, TLSA, ...
