[![Module Tests](https://github.com/msimerson/dns-resource-record/actions/workflows/ci-test.yml/badge.svg)](https://github.com/msimerson/dns-resource-record/actions/workflows/ci-test.yml)
[![Coverage Status](https://coveralls.io/repos/github/msimerson/dns-resource-record/badge.svg?branch=master)](https://coveralls.io/github/msimerson/dns-resource-record?branch=master)

# dns-resource-record

DNS resource record parser, validator, importer, and exporter.


## SYNOPSIS

This module is used to:

- validate well formedness and RFC compliance of DNS resource records
- import RRs from:
    - [x] JSON
    - [x] [BIND](https://www.isc.org/bind/) zone [file format](https://bind9.readthedocs.io/en/latest/reference.html#zone-file)
    - [x] tinydns [data format](https://cr.yp.to/djbdns/tinydns-data.html)
- export RRs to:
    - [x] BIND zone file format
    - [x] tinydns data format

This module intends to import and export RFC compliant DNS resource records. Please [raise an issue](https://github.com/msimerson/dns-resource-record/issues) if you cannot pass a valid resource record or you can pass an invalid resource record.


## USAGE

Load the index for access to all RR types:

```js
const RR = require('dns-resource-record')
```

### EXAMPLES

```js
const RR = require('dns-resource-record')
const exampleRRs = {
    A: {
        name   : 'test.example.com',
        type   : 'A',
        address: '192.0.2.127',
        ttl    : 3600,
    },
    AAAA: {
        name   : 'test.example.com',
        type   : 'AAAA',
        address: '2605:7900:20:a::4',
        ttl    : 3600,
    },
    SOA: {
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
    }
}
try {
    console.log(new RR.SOA(exampleRRs.SOA))
    SOA(11) [Map] {
        'name' => 'example.com',
        'ttl' => 3600,
        'class' => 'IN',
        'type' => 'SOA',
        'mname' => 'matt.example.com.',
        'rname' => 'ns1.example.com.',
        'serial' => 1,
        'refresh' => 7200,
        'retry' => 3600,
        'expire' => 1209600,
        'minimum' => 3600
    }
}
catch (e) {
    // invalid RRs will throw
    console.error(e)
}
```

Validate records by passing a properly formatted JS object to the record-specific class. To validate an A record:

```js
const A = require('dns-resource-record').A
const validatedA = new A(exampleRRs.A)
```

Manipulate the validated record using pattern named setter functions:

```js
console.log(validatedA.toBind())
test.example.com    3600    IN  A   192.0.2.127

validatedA.setAddress('192.0.2.128')
console.log(validatedA.toBind())
test.example.com    3600    IN  A   192.0.2.128
```

The setter functions are named: `set` + `Field`, where field is the resource record field name to modify. Multi-word names are camel cased, so a field named `Certificate Usage` would have a setter named `setCertificateUsage`. You can get the field names with `getFields()`:

```js
> validatedA.getFields()
[ 'name', 'ttl', 'class', 'type', 'address' ]
```

## FUNCTIONS

### toBind

Validate a record and export to BIND format.

```js
console.log(new RR.A(exampleRRs.A).toBind())
test.example.com    3600    IN  A   192.0.2.127

console.log(new RR.AAAA(exampleRRs.AAAA).toBind())
test.example.com    3600    IN  AAAA    2605:7900:20:a::4
```

### toTinydns

Validate a record and export to tinydns format:

```js
console.log(new RR.A(exampleRRs.A).toTinydns())
+test.example.com:192.0.2.127:3600::
```

### fromTinydns toBind

Convert a tinydns line to BIND:

```js
console.log(new RR.CAA({
  tinyline: ':ns1.example.com:257:\\000\\005issue"http\\072\\057\\057letsencrypt.org":3600::\n'
}).toBind())
ns1.example.com 3600    IN  CAA 0   issue   "http://letsencrypt.org"
```

### set

The DNS validation checks can be bypassed entirely by using 'set':

```js
> validatedA.set('address', 'oops')
A(5) [Map] {
  'name' => 'test.example.com',
  'ttl' => 3600,
  'class' => 'IN',
  'type' => 'A',
  'address' => 'oops'
}
```

Consider this a "running with scissors" mode.


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
| **DNSKEY** |:white_check_mark:|                  |:white_check_mark:|                  |:white_check_mark:|
| **DS**     |:white_check_mark:|                  |:white_check_mark:|                  |:white_check_mark:|
| **HINFO**  |:white_check_mark:|                  |                  |                  |:white_check_mark:|
|**IPSECKEY**|                  |                  |                  |                  |                  |
| **LOC**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **MX**     |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **NAPTR**  |:white_check_mark:|:white_check_mark:|:white_check_mark:|                  |:white_check_mark:|
| **NS**     |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **PTR**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **SMIMEA** |:white_check_mark:|                  |:white_check_mark:|                  |                  |
| **SOA**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **SPF**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **SRV**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **SSHFP**  |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **TLSA**   |:white_check_mark:|                  |:white_check_mark:|                  |                  |
| **TXT**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **URI**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|


## TIPS

- Domain names are stored fully qualified, absolute, with the trailing dot.
    - Master Zone File expansions exist at another level
- fromBIND is regex based and is naive. [dns-zone-validator](https://github.com/msimerson/dns-zone-validator) has a much more robust parser.
- 


## TODO

- [x] Change all IPs to use [RFC example/doc](https://en.wikipedia.org/wiki/Reserved_IP_addresses) address space
- [x] change all domains to use reserved doc names
- [x] import tests from nictool/server/t/12_records.t
- [x] add defaults for empty values like TTL
- [x] DNSSEC RRs, except: RRSIG, NSEC, NSEC3, NSEC3PARAM
- [ ] Additional RRs?: KX, CERT, DHCID, TLSA, ...
