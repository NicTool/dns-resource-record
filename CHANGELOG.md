
#### 1.N.N - YYYY-MM-DD


#### 1.1.0 - 2022-04-22

- feat(tinydns): add ipv4toOctal, octalToIPv4, base64toOctal, octalToBase64
- feat(DNSKEY,DS,IPSECKEY,TLSA): added to/fromTinydns support
- feat(NAPTR): finished fromTinydns
- feat(bindline & tinyline): pass in opts (was only line), so defaults (serial, ttl, etc) can be passed in.
- fix(SSHFP): algo & fptype are 1 byte, not 2
- fix:(cname): fully qualify the target
- test: add tinydns.unpackDomainName, ipv4toOctal, octalToIPv4
- test(SRV): add another test case (found a bug in NicTool 2)
- test(IPSECKEY): expand test coverage
- tinydns.unpackdomain: return fqdn + length, for RRs where the FQDN is part of the byte stream


#### 1.0.1 - 2022-04-19

- feat(IPSECKEY): added basic support
- doc(README): update for ES module usage
- fix: call is[8|16]BitInt() correctly
- style: replace this.constructor with class name
- test: show more results in test output
- test(CERT): added two test cases
- test(KEY): added valid test


#### 1.0.0 - 2022-04-18

- style: move rr/index to ./rr
- test: add base.getRdataFields
- style(esm): convert from CJS to ESM (ES6 module)
- test: add base.getRdataFields


#### 0.9.9 - 2022-04-14

- feat: parser improvements (DNSKEY, HINFO, NAPTR, SOA, TLSA, TXT)
- CAA: more robust fromBind parser
- SOA: leave $TTL and $ORIGIN to dns-zone
- test/base: improve invalid tests, check error message against expected
- test/rr: update tests with expected error messages
- README: move some content to web links


#### 0.9.8 - 2022-04-07

- url updates
- fix: txt records
- feat: add index.citeRFC
- docs: updates


#### 0.9.7 - 2022-03-29

- index
    - previousName -> previousOwner
    - export a TYPE_MAP (id => name)
- isValidHostname: allow \ char
- add the word 'RFC' in error messages citing RFCs
- when rejecting hostname, show the rejected character
- maradns: add export support
- add index.citeRFC


#### 0.9.6 - 2022-03-27

- rr\*: rename name -> owner (not overloaded)
- RFC 4034: letters in DNS names are lower cased
- README: added definitions
- repo: move from msimerson -> NicTool org
- add macos testing
- add CERT, KEY, NSEC, NSEC3, NSEC3PARAM, OPENPGPKEY, SIG


#### 0.9.5 - 2022-03-26

- README: add docs for getRFCs()
- dnskey: fix copy/paste errors
- HINFO: add fromBind
- RR.owner: if owner is same as previous, suppress (when sameOwner option is set)
- master: NODE_ENV=cov when running coverage
- TXT: pass along zone_opts


#### 0.9.4 - 2022-03-24

- add: getComment
- zone_opts, for influencing output of toBind
- normalize hostnames to lower case
- add tests: fullyQualify, getFQDN
- AAAA
    - compress: rewrote per RFC 5952, added tests
    - internally store address in expanded notation
- fromTinydns: apply correct semantics for 'x' handling
- fullyQualify
    - special handling for @
    - consider $ORIGIN
- add uc hex chars to ip6 compress


#### 0.9.3 - 2022-03-22

- hasValidLabels: remove trailing dot, else split returns empty string
- rename fullyQualified -> isFullyQualified
- rename validHostname -> isValidHostname
- set('type') no longer falls back on constructor.name (didn't reliably inherit)
- new fns: getTinyFQDN, fullyQualify, getPrefix, getFQDN
- when loading RR classes, ignore files that don't end with .js
- rr/txt: support data as array (improves idempotency)
- fromTinydns: fully qualify hostnames
- toTinydns: strip trailing . upon export
- rename getCommonFields -> getPrefixFields
- TXT: import BIND format w/o mangling WS
- SPF inherits from TXT


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
