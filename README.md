[![Module Tests](https://github.com/NicTool/dns-resource-record/actions/workflows/ci.yml/badge.svg)](https://github.com/NicTool/dns-resource-record/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/NicTool/dns-resource-record/badge.svg?branch=master)](https://coveralls.io/github/NicTool/dns-resource-record?branch=master)

# dns-resource-record

DNS resource record parser, validator, importer, and exporter for node.js & browsers.

## SYNOPSIS

This module is used to:

- validate well formedness and RFC compliance of DNS resource records
- import RRs to and from the following formats:

|                      **RR format**                       |     **import**     |     **export**     |
| :------------------------------------------------------: | :----------------: | :----------------: |
|                         **JSON**                         | :white_check_mark: | :white_check_mark: |
|          **[BIND](https://www.isc.org/bind/)**           | :white_check_mark: | :white_check_mark: |
| **[Tinydns](https://cr.yp.to/djbdns/tinydns-data.html)** | :white_check_mark: | :white_check_mark: |
|                       **MaraDNS**                        |                    | :white_check_mark: |
|                          **JS**                          | :white_check_mark: | :white_check_mark: |

This package intends to import and export RFC compliant DNS resource records. Please [raise an issue](https://github.com/NicTool/dns-resource-record/issues) if a valid resource record fails to pass or an invalid resource record passes.

This package is for working with _individual_ Resource Records. For working with zones of RRs, use [dns-zone](https://github.com/NicTool/dns-zone).

## USAGE

Load the index for access to all RR types:

```js
import * as RR from '@nictool/dns-resource-record'
```

### EXAMPLES

```js
const exampleRRs = {
    A: {
        owner  : 'test.example.com.',
        type   : 'A',
        address: '192.0.2.127',
        ttl    : 3600,
    },
    AAAA: {
        owner  : 'test.example.com.',
        type   : 'AAAA',
        address: '2605:7900:20:a::4',
        ttl    : 3600,
    },
    SOA: {
        owner  : 'example.com.',
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
        'owner' => 'example.com.',
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
const validatedA = new RR.A(exampleRRs.A)
```

Manipulate the validated record using pattern named setters:

```js
console.log(validatedA.toBind())
test.example.com.    3600    IN  A   192.0.2.127

validatedA.setAddress('192.0.2.128')
console.log(validatedA.toBind())
test.example.com.    3600    IN  A   192.0.2.128
```

The setters are named: `set` + `Field`, where field is the resource record field name to modify. Multi-word names are camel cased, so a field named `Certificate Usage` has a setter named `setCertificateUsage`. The RFCs aren't always consistent regarding RR field names so aliases are permissible for interoperability.

## FUNCTIONS

Get the field names for each RR type with `getFields()`:

```js
> import * as RR from 'dns-resource-record'
> new RR.A(null).getFields()
[ 'owner', 'ttl', 'class', 'type', 'address' ]

> new RR.PTR(null).getFields()
[ 'owner', 'ttl', 'class', 'type', 'dname' ]

> new RR.SSHFP(null).getFields()
[ 'owner', 'ttl', 'class', 'type', 'algorithm', 'fptype', 'fingerprint' ]
```

Get a list of RFCs for references about each RR type:

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
  'owner' => 'test.example.com',
  'ttl' => 3600,
  'class' => 'IN',
  'type' => 'A',
  'address' => 'oops'
}
```

Consider this a "running with scissors" mode.

## Supported Records

This module intends to support all current (ie, not officially deprecated) DNS RRs **and** all RRs that are in active use on the internet.

PRs are welcome, especially PRs with tests.

|     **RR**     |     **toBind**     |   **toTinydns**    |    **fromBind**    |  **fromTinydns**   |
| :------------: | :----------------: | :----------------: | :----------------: | :----------------: |
|     **A**      | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|    **AAAA**    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|    **APL**     | :white_check_mark: | :white_check_mark: | :white_check_mark: |                    |
|    **CAA**     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|    **CERT**    | :white_check_mark: |                    | :white_check_mark: |                    |
|   **CNAME**    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|   **DHCID**    | :white_check_mark: | :white_check_mark: | :white_check_mark: |                    |
|   **DNAME**    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|   **DNSKEY**   | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|     **DS**     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|   **HINFO**    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|    **HIP**     | :white_check_mark: | :white_check_mark: | :white_check_mark: |                    |
|   **HTTPS**    | :white_check_mark: |                    | :white_check_mark: |                    |
|  **IPSECKEY**  | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|    **KEY**     |                    |                    |                    |                    |
|     **KX**     | :white_check_mark: | :white_check_mark: | :white_check_mark: |                    |
|    **LOC**     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|     **MX**     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|   **NAPTR**    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|     **NS**     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|    **NSEC**    | :white_check_mark: |                    | :white_check_mark: |                    |
|   **NSEC3**    | :white_check_mark: | :white_check_mark: | :white_check_mark: |                    |
| **NSEC3PARAM** |                    |                    |                    |                    |
|    **NXT**     |                    |                    |                    |                    |
| **OPENPGPKEY** |                    |                    |                    |                    |
|    **PTR**     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|     **RP**     | :white_check_mark: | :white_check_mark: | :white_check_mark: |                    |
|   **RRSIG**    |                    |                    |                    |                    |
|    **SIG**     |                    |                    |                    |                    |
|   **SMIMEA**   | :white_check_mark: |                    | :white_check_mark: |                    |
|    **SOA**     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|    **SPF**     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|    **SRV**     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|   **SSHFP**    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|    **SVCB**    | :white_check_mark: |                    | :white_check_mark: |                    |
|    **TLSA**    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|    **TSIG**    |                    |                    |                    |                    |
|    **TXT**     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|    **URI**     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
|    **WKS**     | :white_check_mark: |                    | :white_check_mark: |                    |

## TIPS

- Domain owner names are:
  - stored fully qualified, aka absolute.
  - normalized to lower case, because:
    - DNS is case insensitive (see RFCs 4343, 1035, 1034)
    - this library enforces duplicate suppression
    - DNSSEC canonicalization (see RFC 4034)
    - wire format for most RRs require it
  - Master Zone File expansions exist in [dns-zone](https://github.com/NicTool/dns-zone)
- to{Bind|MaraDNS} output can be influenced (suppress TTL, class, relative domain names) with an options object. See it in `bin/dns-zone` in the [dns-zone](https://github.com/NicTool/dns-zone) package.

## SEE ALSO

- [Dictionary of DNS terms](https://nictool.github.io/web/Dictionary)
- [Wikipedia, List of DNS Record Types](https://en.wikipedia.org/wiki/List_of_DNS_record_types)
- @nictool/[dns-zone](https://www.npmjs.com/package/@nictool/dns-zone)
- @nictool/[dns-nameserver](https://www.npmjs.com/package/@nictool/dns-nameserver)

## TODO

- [ ] export a web page for each RR type

## DEVELOP

- There are no dependencies. That's no accident.
- ES modules for use by node.js and browser
- Platform independence is a goal
  - [x] CI tests are on linux, windows, and macos
