
#### 1.N.N - YYYY-MM-DD

#### 0.9.3 - 2022-03-21

- hasValidLabels: remove trailing dot, else split returns empty string
- add config file:
    - label.max\_len
    - fqdn.max\_len

#### 0.9.2 - 2022-03-18

- mx: weight -> preference
- ds: keytag -> key tag (consistent naming)
- mx: add null MX test
- more use of this.getRFCs in error messages
- added getTinydnsGeneric
- on `index.is*` functions which throw, use declaratively
- class: add NONE and ANY
- validHostname: allow / char
- use \_\_dirname to find RR mods


#### 0.9.1 - 2022-03-14

- TLSA, SMIMEA: add BIND support #13


#### 0.9.0 - 2022-03-10

- added null object instantiation
- added `getTypeId`, `getDescription`, `getRdataFields`, `getQuotedFields`
- tinydns: refactored fromTinydnsGeneric
- add `RR.toBind()` for most
- spf: corrected RFC IDs
- rr/\*: refactor init into RR.constructor
- ds,dnskey: add to/from BIND support
- README: significant expansion
- tests: more signal, less noise
- tests: import tests from nictool 2


#### 0.8.1 - 2022-03-08

- use RFC example IPs and zone names


#### 0.8.0 - 2022-02-01

- fromBind for: A, AAAA, CNAME, TXT, CNAME, TXT, LOC, MX, NS, SOA, PTR, SPF, SSHFP, URI, CAA, DNAME, NAPTR
- add fromTinydns: LOC
- rr/\*: add getFields


#### 0.7.0 - 2021-10-26

- tinydns: added octalToHex, octalToUInt16, unpackDomainName, octalToInt8
- AAAA: added fromTinydns, compress, expand
- CAA, CNAME, DNAME, SPF, SSHFP, SRV, URI: added fromTinydns
- add tests for getRFCs


#### 0.6.0 - 2021-10-25

- tinydns: added octalToChar
- A, MX, NS, PTR, SOA, TXT: added fromTinydns


#### 0.5.1 - 2021-10-25

- LOC: added toTinydns
- tinydns: add UInt32toOctal
- SRV: added support


#### 0.5.0 - 2021-10-24

- NAPTR: add toTinydns
- tinydns: remove sprintf-js dependency


#### 0.4.0 - 2021-10-22

- CAA, DNAME, SSHFP, URI: add toTinydns
- lib/tinydns: added packHex and UInt16AsOctal


#### 0.3.1 - 2021-10-21

- update index.js to also export RR sub classes
- update README examples


#### 0.3.0 - 2021-10-21

- add getRFCs to all RR types
- populate this.id with IANA type ID
- toBind: use tabs for exported WS
- CAA, DNAME, NAPTR, SSHFP, URI: add toBind, tests


#### 0.2.3 - 2021-10-21

- refactored classes into separate files
- TXT, SOA, MX, CNAME, PTR, SRV: add toBind and toTinydns
- SOA: add setMinimum
- lib/tinydns: added escapeOct & packDomainName
- PTR, SRV: added tests


#### 0.2.2 - 2021-10-20

- add tests/*
- A, AAAA, add toBind and toTinydns()
- add .release


#### 0.2.1 - 2021-10-16

- additional RR formats started, weakly validated


#### 0.2.0 - 2021-10-16

- initial release & name grab
