[![Module Tests](https://github.com/msimerson/dns-resource-record/actions/workflows/ci-test.yml/badge.svg)](https://github.com/msimerson/dns-resource-record/actions/workflows/ci-test.yml)
[![Coverage Status](https://coveralls.io/repos/github/msimerson/dns-resource-record/badge.svg?branch=master)](https://coveralls.io/github/msimerson/dns-resource-record?branch=master)

# dns-resource-record

DNS resource record parser, validator, importer, and exporter.


## SYNOPSIS

This module is used to:

- validate well formedness and RFC compliance of DNS resource records
- import RRs from:
    - JS object
    - JSON
    - [BIND](https://www.isc.org/bind/) zone [file format](https://bind9.readthedocs.io/en/latest/reference.html#zone-file)
    - tinydns [data format](https://cr.yp.to/djbdns/tinydns-data.html)
- export RRs to:
    - BIND zone file format
    - tinydns data format
    - JS object
    - JSON

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
    console.error(e.message) // invalid RRs throw
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

The setter functions are named: `set` + `Field`, where field is the resource record field name to modify. Multi-word names are camel cased, so a field named `Certificate Usage` would have a setter named `setCertificateUsage`.

## FUNCTIONS

Get the field names for each RR type with `getFields()`:

```js
> const RR = require('dns-resource-record')
> new RR.A(null).getFields()
[ 'name', 'ttl', 'class', 'type', 'address' ]

> new RR.PTR(null).getFields()
[ 'name', 'ttl', 'class', 'type', 'dname' ]

> new RR.SSHFP(null).getFields()
[ 'name', 'ttl', 'class', 'type', 'algorithm', 'fptype', 'fingerprint' ]
```

Get a list of RFCs for further learning about a RR type:

```js
> new RR.A(null).getRFCs()
[ 1035 ]

> new RR.SRV(null).getRFCs()
[ 2782 ]

> new RR.MX(null).getRFCs()
[ 1035, 2181, 7505 ]
```

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

| **RR**     | **toBind**       | **toTinydns**    | **fromBind**     |  **fromTinydns** |
|:---------: |:----------------:|:----------------:|:----------------:|:----------------:|
| **A**      |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **AAAA**   |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **CAA**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **CERT**   |                  |                  |                  |                  |
| **CNAME**  |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **DNAME**  |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **DNSKEY** |:white_check_mark:|                  |:white_check_mark:|                  |
| **DS**     |:white_check_mark:|                  |:white_check_mark:|                  |
| **HINFO**  |:white_check_mark:|                  |:white_check_mark:|                  |
|**IPSECKEY**|                  |                  |                  |                  |
| **KEY**    |                  |                  |                  |                  |
| **LOC**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **MX**     |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **NAPTR**  |:white_check_mark:|:white_check_mark:|:white_check_mark:|                  |
| **NS**     |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **NSEC**   |                  |                  |                  |                  |
| **NSEC3**  |                  |                  |                  |                  |
| **NSEC3PARAM**|               |                  |                  |                  |
| **OPENPGPKEY**|               |                  |                  |                  |
| **PTR**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **RRSIG**  |                  |                  |                  |                  |
| **SIG**    |                  |                  |                  |                  |
| **SMIMEA** |:white_check_mark:|                  |:white_check_mark:|                  |
| **SOA**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **SPF**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **SRV**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **SSHFP**  |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **TLSA**   |:white_check_mark:|                  |:white_check_mark:|                  |
| **TXT**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|
| **URI**    |:white_check_mark:|:white_check_mark:|:white_check_mark:|:white_check_mark:|


## TIPS

- Domain names are:
    - stored fully qualified, aka absolute.
    - normalized to lower case
        - DNS is case insensitive (see RFCs 4343, 1035, 1034)
        - this library enforces duplicate suppression
        - DNSSEC canonicalization (see RFC 4034)
        - wire format for most RRs require it
    - Master Zone File expansions exist at another level
    - domain 
- fromBIND is regex based and is naive. [dns-zone-validator](https://github.com/msimerson/dns-zone-validator) has a much more robust parser.
- toBind output (suppress TTL, class, relative domain names) can be influenced by passing in an options object. See it in `bin/import.js` in the [dns-zone-validator](https://github.com/msimerson/dns-zone-validator) package.


## TODO

- [x] Change all IPs to use [RFC example/doc](https://en.wikipedia.org/wiki/Reserved_IP_addresses) address space
- [x] change all domains to use reserved doc names
- [x] import tests from nictool/server/t/12_records.t
- [x] add defaults for empty values like TTL
- [x] DNSSEC RRs: DS, NSEC, NSEC3, NSEC3PARAM, RRSIG
- [x] CERT RRs: CERT, KEY, SIG, OPENPGPKEY
- [ ] KX, DHCID, HIP, RP
- [ ] add toWire, exports in wire/network format
- [ ] RFC 4034: if the type of RR is NS, MD, MF, CNAME, SOA, MB,
      MG, MR, PTR, HINFO, MINFO, MX, RP, AFSDB, RT, SIG, PX, NXT,
      NAPTR, KX, SRV, DNAME, A6, RRSIG, or NSEC, all uppercase 
      letters in the DNS names contained within the RDATA are replaced by the lowercase letters;
- [ ] LOC record ingest/out isn't consistent with API
- [ ] handling unknown RR types: RFC 3597
- [ ] export a web page for each RR type

## DEVELOP

- this package has no dependencies. That's no accident.
- eventually this will be used a node.js app & a browser based app
    - so, ESM, eventually
- CI tests are on linux & windows
