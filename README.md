[![Module Tests][ci-img]][ci-url]
[![Test Coverage][cov-img]][cov-url]

# dns-resource-record

DNS resource record parser, validator, importer, and exporter for node.js & browsers

**Quick Links:** [Getting Started](#getting-started) | [API Reference](#api-reference) | [Browser/CDN](#browser--cdn) | [Supported Records](#supported-records) | [Contributing](#development)

## Overview

This module validates, imports, and exports DNS resource records (RRs) with rigorous RFC compliance and robust test coverage.

**What you can do:**

- **Validate** DNS records for RFC compliance and well-formedness
- **Parse/Import** records from BIND zone files, tinydns data files, or JS objects
- **Export** records to BIND, tinydns, MaraDNS, JSON, or wire format
- **Manipulate** validated records with type-safe setters
- **Convert** between formats seamlessly (e.g., tinydns → BIND -> wire)

**Scope:** This package handles individual Resource Records. For zone file operations, see [dns-zone](https://github.com/NicTool/dns-zone).

**Quality:** RFC compliance is a first-class concern. If you encounter a valid RR that fails to parse or an invalid RR that passes validation, please [open an issue](https://github.com/NicTool/dns-resource-record/issues).

## Supported Records

This module supports all current DNS RRs in active use on the internet.

|     Usage     |                   **Resource Record Types**                   |
| :-----------: | :-----------------------------------------------------------: |
|   _Common_    |       A, AAAA, CNAME, HTTPS, MX, NS, PTR, SOA, SRV, TXT       |
| _Less Common_ | APL, CERT, DHCID, DNAME, HIP, KX, LOC, NAPTR, SVCB, TSIG, URI |
|  _Security_   |        CAA, IPSECKEY, OPENPGPKEY, SMIMEA, SSHFP, TLSA         |
|   _DNSSEC_    |          DNSKEY, DS, NSEC, NSEC3, NSEC3PARAM, RRSIG           |
|  _Obsolete_   |              HINFO, KEY, NXT, RP, SIG, SPF, WKS               |
|   _Generic_   |            UNKNOWN (any TYPEnnn, per [RFC 3597][])            |

[rfc 3597]: https://www.rfc-editor.org/rfc/rfc3597

Types with no implementation here are handled as opaque rdata by the `UNKNOWN`
class, and `classFor('TYPE731')` resolves a type name or id to its class:

```js
new RR.UNKNOWN({ owner: 'a.example.', ttl: 3600, typeId: 731, rdata: 'abcdef012345' }).toBind()
// 'a.example.\t3600\tIN\tTYPE731\t\# 6 abcdef012345\n'
```

See `rr/unknown.js` for the details.

## Getting Started

### Installation

```sh
npm install @nictool/dns-resource-record
```

### ESM and CommonJS

The package ships both ESM and CJS, selected automatically via the package `exports` map:

```js
// ESM
import * as RR from '@nictool/dns-resource-record'
import RR, { A, TXT } from '@nictool/dns-resource-record'
```

```js
// CommonJS
const RR = require('@nictool/dns-resource-record')
const { A, TXT } = require('@nictool/dns-resource-record')
```

The default export (the base `RR` class) is reached as `require('@nictool/dns-resource-record').default` from CommonJS.

### Validation

Validate an A record:

```js
import * as RR from '@nictool/dns-resource-record'

const validA = new RR.A({
  owner: 'example.com.',
  address: '192.0.2.1',
  ttl: 3600,
})

console.log(validA.toBind())
// example.com.	3600	IN	A	192.0.2.1
```

Invalid records throw immediately:

```js
try {
  new RR.A({ owner: 'example.com.', address: 'not-an-ip', ttl: 3600 })
} catch (err) {
  console.error(err.message) // Error: A address must be IPv4
}
```

This library enforces RFC-compliance during construction, catching errors early.

---

## API Reference

### Understanding Record Structure

Every DNS record has these standard fields:

- **owner** — The domain name this record belongs to (always fully qualified, e.g., `example.com.`)
- **type** — The record type (A, AAAA, MX, TXT, etc.)
- **ttl** — Time to live in seconds
- **class** — Almost always `IN` (Internet); omitted in examples

Plus **rdata fields** specific to each record type (e.g., `address` for A records, `preference`/`exchange` for MX records).

### Core Workflows

#### 1. **Validate & Create** — Use the Constructor

When you have data in JavaScript object form:

```js
new RR.SOA({
  owner: 'example.com.',
  mname: 'ns1.example.com.',
  rname: 'hostmaster.example.com.',
  serial: 2024042201,
  refresh: 7200,
  retry: 3600,
  expire: 1209600,
  minimum: 3600,
  ttl: 3600,
})
```

**When to use:** Building records programmatically, validating user input, working with API responses.

---

#### 2. **Parse BIND Format** — Use `fromBind()`

When you have a line from a BIND zone file:

```js
const rr = RR.A.fromBind('www.example.com.  3600  IN  A  192.0.2.1\n')
console.log(rr.get('address')) // '192.0.2.1'
```

**When to use:** Processing BIND zone files, DNS configs, or standard zone file exports.

---

#### 3. **Parse Tinydns Format** — Use `fromTinydns()`

When you have a line from a tinydns data file:

```js
const rr = RR.A.fromTinydns('+www.example.com:192.0.2.1:3600::\n')
console.log(rr.get('address')) // '192.0.2.1'
```

**When to use:** Working with djbdns/tinydns configurations, or when parsing tinydns data files.

---

#### 4. **Export to BIND** — Use `toBind()`

Convert any validated record to BIND zone file format:

```js
new RR.MX({
  owner: 'example.com.',
  preference: 10,
  exchange: 'mail.example.com.',
  ttl: 3600,
}).toBind()
// example.com.	3600	IN	MX	10	mail.example.com.
```

**When to use:** Generating zone files, displaying records for editing, exporting to BIND nameservers.

---

#### 5. **Export to Tinydns** — Use `toTinydns()`

Convert to tinydns data file format:

```js
new RR.A({
  owner: 'example.com.',
  address: '192.0.2.1',
  ttl: 3600,
}).toTinydns()
// +example.com:192.0.2.1:3600::
```

**When to use:** Generating tinydns data files, migrating to djbdns, or integrating with tinydns tooling.

---

#### 6. **Round-Trip Conversion**

Parse from one format, export to another:

```js
// tinydns → BIND
const fromTiny = RR.CAA.fromTinydns(
  ':ns1.example.com:257:\\000\\005issue"http\\072\\057\\057letsencrypt.org":3600::\n',
)
console.log(fromTiny.toBind())
// ns1.example.com.	3600	IN	CAA	0	issue	"http://letsencrypt.org"
```

**When to use:** DNS migrations, format conversions, tool interoperability.

---

### Manipulating Records

Use **setter methods** to modify validated records. Setter names follow the pattern `set` + `FieldName` (camelCased):

```js
const a = new RR.A({
  owner: 'example.com.',
  address: '192.0.2.1',
  ttl: 3600,
})

a.setAddress('192.0.2.2')
a.setTtl(7200)

console.log(a.toBind())
// example.com.	7200	IN	A	192.0.2.2
```

Setters include validation. Invalid values throw with helpful error messages.

For a list of available setters, check `getFields('rdata')` for your record type:

```js
new RR.SSHFP(null).getFields('rdata')
// ['algorithm', 'fptype', 'fingerprint']
// So use: setAlgorithm(), setFptype(), setFingerprint()
```

---

### Metadata Methods

Get information about record types:

#### `getFields([section])`

Get field names for a record type. Pass `'rdata'` to get only the custom fields:

```js
new RR.A(null).getFields() // ['owner', 'ttl', 'class', 'type', 'address']
new RR.A(null).getFields('rdata') // ['address']
new RR.MX(null).getFields('rdata') // ['preference', 'exchange']
```

#### `getRFCs()`

Get RFC references for a record type:

```js
new RR.A(null).getRFCs() // [1035]
new RR.MX(null).getRFCs() // [1035, 2181, 7505]
new RR.SRV(null).getRFCs() // [2782]
```

#### `getCanonical()`

Get a record with all fields populated with default/canonical values:

```js
new RR.AAAA(null).getCanonical()
// {
//   owner: 'host.example.com.',
//   address: '2001:0db8:0020:000a:0000:0000:0000:0004',
//   class: 'IN',
//   ttl: 3600,
//   type: 'AAAA'
// }
```

#### `toJSON()` / `JSON.stringify()`

Serialize a record to a plain object:

```js
const a = new RR.A({ owner: 'example.com.', address: '192.0.2.1', ttl: 3600 })
JSON.stringify(a)
// {"owner":"example.com.","ttl":3600,"class":"IN","type":"A","address":"192.0.2.1"}
```

---

### Advanced: Bypassing Validation

The `set()` method bypasses validation (use carefully):

```js
record.set('address', 'invalid-value')
// Works, but now the record is malformed — useful only for testing or low-level manipulation
```

**Note:** Validation is there to protect data integrity. Use at your own risk.

---

## Browser & CDN

Use this module directly in browsers via CDN:

```html
<!DOCTYPE html>
<html>
  <head>
    <title>DNS Record Validator</title>
  </head>
  <body>
    <h1>DNS Record Validator</h1>
    <pre id="output"></pre>

    <script type="module">
      // Import from unpkg (or jsdelivr, esm.sh)
      import * as RR from 'https://unpkg.com/@nictool/dns-resource-record@latest/dist/dns-rr.min.js'

      // Use just like Node.js
      const record = new RR.A({
        owner: 'example.com.',
        address: '192.0.2.1',
        ttl: 3600,
      })

      document.getElementById('output').textContent = record.toBind()
    </script>
  </body>
</html>
```

**Available CDNs:**

- **unpkg:** `https://unpkg.com/@nictool/dns-resource-record/dist/dns-rr.min.js`
- **jsdelivr:** `https://cdn.jsdelivr.net/npm/@nictool/dns-resource-record/dist/dns-rr.min.js`
- **esm.sh:** `https://esm.sh/@nictool/dns-resource-record`

**Live example:** See [nictool.github.io/builder/](https://nictool.github.io/builder/) for an interactive DNS record editor using this library.

---

## Important Concepts

### Domain Name Normalization

Domain owner names are:

- **Stored fully qualified** (absolute), e.g., `example.com.` not `example.com`
- **Normalized to lowercase** because:
  - DNS is case-insensitive (RFC 4343, RFC 1035)
  - This library enforces automatic duplicate suppression
  - DNSSEC canonicalization requires it (RFC 4034)
  - Wire format for most RRs requires lowercase

**Example:**

```js
const r = new RR.A({ owner: 'EXAMPLE.COM.', address: '192.0.2.1', ttl: 3600 })
r.get('owner') // 'example.com.' — uppercase normalized to lowercase
```

Owner names are required to be fully qualified (trailing dot). Unqualified
names throw at construction; this library does not add the dot for you.

### Relative vs Absolute Names

Master zone file expansions (relative domain names) are handled by [dns-zone](https://github.com/NicTool/dns-zone). This library works only with fully qualified names.

### Export Options

The `toBind()` method accepts a zone-options object (typically supplied by
[dns-zone](https://github.com/NicTool/dns-zone) when emitting full zone files)
to omit redundant per-record output:

```js
record.toBind({
  origin: 'example.com.', // strips matching suffix from owner; emits '@' for an exact match
  ttl: 3600, // the zone default; lets `hide.ttl` skip records whose TTL matches it
  previousOwner: 'example.com.', // lets `hide.sameOwner` blank the owner column when it repeats
  hide: {
    ttl: true, // omit TTL when it equals the zone default
    class: true, // omit class column (usually IN)
    sameOwner: true, // omit owner when it matches `previousOwner`
    origin: true, // shorten owners relative to `origin`
  },
})
```

See [dns-zone](https://github.com/NicTool/dns-zone) for the full per-zone pipeline that supplies these options.

## Development

No external dependencies. Runs on node.js and modern browsers.

**Key scripts:**

- `npm test` — Run all tests with node's built-in test runner
- `npm run watch` — Run tests in watch mode during development
- `npm run lint` — Check code with ESLint
- `npm run format` — Auto-format with Prettier and fix linting issues
- `npm run build` — Regenerate the browser and CommonJS bundles in `dist/`
- `npm run test:coverage` — Generate test coverage report

**Architecture:**

- **rr.js** — Base class with shared DNS logic and validation
- **rr/\*.js** — Individual RR type implementations
- **test/\*.js** — Comprehensive test suite for each RR type

## References

- [DNS Record Types (Wikipedia)](https://en.wikipedia.org/wiki/List_of_DNS_record_types)
- [DNS Terminology (NicTool Dictionary)](https://nictool.github.io/Dictionary)
- [dns-zone](https://www.npmjs.com/package/@nictool/dns-zone) — Zone file operations
- [dns-nameserver](https://www.npmjs.com/package/@nictool/dns-nameserver) — Nameserver management

---

[ci-img]: https://github.com/NicTool/dns-resource-record/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/NicTool/dns-resource-record/actions/workflows/ci.yml
[cov-img]: https://coveralls.io/repos/github/NicTool/dns-resource-record/badge.svg
[cov-url]: https://coveralls.io/github/NicTool/dns-resource-record
[bind-url]: https://www.isc.org/bind/
[knot-url]: https://www.knot-dns.cz
[nsd-url]: https://www.nlnetlabs.nl/projects/nsd/about/
[pdns-url]: https://www.powerdns.com/powerdns-authoritative-server
