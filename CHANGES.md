
#### 1.N.N - YYYY-MM-DD


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