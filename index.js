const typeMap = {}

import RR from './rr.js'
import A from './rr/a.js'
import AAAA from './rr/aaaa.js'
import CAA from './rr/caa.js'
import CERT from './rr/cert.js'
import CNAME from './rr/cname.js'
import DNAME from './rr/dname.js'
import DNSKEY from './rr/dnskey.js'
import DS from './rr/ds.js'
import HINFO from './rr/hinfo.js'
import IPSECKEY from './rr/ipseckey.js'
import KEY from './rr/key.js'
import LOC from './rr/loc.js'
import MX from './rr/mx.js'
import NAPTR from './rr/naptr.js'
import NS from './rr/ns.js'
import NSEC from './rr/nsec.js'
import NSEC3 from './rr/nsec3.js'
import NSEC3PARAM from './rr/nsec3param.js'
import NXT from './rr/nxt.js'
import OPENPGPKEY from './rr/openpgpkey.js'
import PTR from './rr/ptr.js'
import RRSIG from './rr/rrsig.js'
import SIG from './rr/sig.js'
import SMIMEA from './rr/smimea.js'
import SOA from './rr/soa.js'
import SPF from './rr/spf.js'
import SRV from './rr/srv.js'
import SSHFP from './rr/sshfp.js'
import TLSA from './rr/tlsa.js'
import TSIG from './rr/tsig.js'
import TXT from './rr/txt.js'
import URI from './rr/uri.js'
import WKS from './rr/wks.js'

export default RR

export {
  A,
  AAAA,
  CAA,
  CERT,
  CNAME,
  DNAME,
  DNSKEY,
  DS,
  HINFO,
  IPSECKEY,
  KEY,
  LOC,
  MX,
  NAPTR,
  NS,
  NSEC,
  NSEC3,
  NSEC3PARAM,
  NXT,
  OPENPGPKEY,
  PTR,
  RRSIG,
  SIG,
  SMIMEA,
  SSHFP,
  SOA,
  SPF,
  SRV,
  TLSA,
  TSIG,
  TXT,
  URI,
  WKS,
  typeMap,
}

for (const c of [
  A,
  AAAA,
  CAA,
  CERT,
  CNAME,
  DNAME,
  DNSKEY,
  DS,
  HINFO,
  IPSECKEY,
  KEY,
  LOC,
  MX,
  NAPTR,
  NS,
  NSEC,
  NSEC3,
  NSEC3PARAM,
  NXT,
  OPENPGPKEY,
  PTR,
  RRSIG,
  SIG,
  SMIMEA,
  SSHFP,
  SOA,
  SPF,
  SRV,
  TLSA,
  TSIG,
  TXT,
  URI,
  WKS,
]) {
  const id = new c(null).getTypeId()
  typeMap[id] = c.name
  typeMap[c.name] = id
}
