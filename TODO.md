# TODO

| **RR**     | **new**            | **toBind**         | **toTinydns**      | **test**           | **fromBind** |  **fromTinydns**   |   getRFCs   |
|:---------: | :----------------: | :----------------: | :----------------: | :----------------: | :----------: | :----------------: | :---------: |
| **A**      | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              | :white_check_mark: | :white_check_mark: |
| **AAAA**   | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              | :white_check_mark: | :white_check_mark: |
| **CAA**    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              | :white_check_mark: | :white_check_mark: |
| **CNAME**  | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              | :white_check_mark: | :white_check_mark: |
| **DNAME**  | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              | :white_check_mark: | :white_check_mark: |
| **DNSKEY** |                    |                    |                    |                    |              |                    |                    |
| **DS**     |                    |                    |                    |                    |              |                    |                    |
| **HINFO**  | :white_check_mark: | :white_check_mark: |                    |                    |              |                    | :white_check_mark: |
|**IPSECKEY**|                    |                    |                    |                    |              |                    |                    |
| **LOC**    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              |                    | :white_check_mark: |
| **MX**     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              | :white_check_mark: | :white_check_mark: |
| **NAPTR**  | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              |                    | :white_check_mark: |
| **NS**     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              | :white_check_mark: | :white_check_mark: |
| **PTR**    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              | :white_check_mark: | :white_check_mark: |
| **SMIMEA** |                    |                    |                    |                    |              |                    |                    |
| **SOA**    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              | :white_check_mark: | :white_check_mark: |
| **SPF**    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              | :white_check_mark: | :white_check_mark: |
| **SRV**    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              | :white_check_mark: | :white_check_mark: |
| **SSHFP**  | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              | :white_check_mark: | :white_check_mark: |
| **TXT**    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              | :white_check_mark: | :white_check_mark: |
| **URI**    | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |              | :white_check_mark: | :white_check_mark: |


# Odds and Ends

- [ ] Change all IPs to use RFC example/doc address space
- [ ] change all domains to use reserved doc names
- [ ] import tests from nictool/server/t/12_records.t
- [x] add defaults for empty values like TTL?
- [ ] DNSSEC RRs, probably not: RRSIG, NSEC, NSEC3, NSEC3PARAM
- [ ] Additional RRs?: KX, CERT, DHCID, TLSA, ...