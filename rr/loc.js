
const RR      = require('./index').RR
const TINYDNS = require('../lib/tinydns')

class LOC extends RR {
  constructor (opts) {
    super(opts)
    this.set('id', 29)

    this.setAddress(opts?.address)
  }

  /****** Resource record specific setters   *******/
  setAddress (val) {
    if (!val) throw new Error('LOC: address is required')

    /*
    ... LOC ( d1 [m1 [s1]] {"N"|"S"} d2 [m2 [s2]]
             {"E"|"W"} alt["m"] [siz["m"] [hp["m"]
             [vp["m"]]]] )
    */
    this.parseLoc(val)

    this.set('address', val)
  }

  getRFCs () {
    return [ 1876 ]
  }

  parseLoc (string) {

    // d1 [m1 [s1]]
    const dms = '(\\d+)\\s+(?:(\\d+)\\s+)?(?:([\\d.]+)\\s+)?'

    // alt["m"] [siz["m"] [hp["m"] [vp["m"]]]]
    const alt = '(-?[\\d.]+)m?(?:\\s+([\\d.]+)m?)?(?:\\s+([\\d.]+)m?)?(?:\\s+([\\d.]+)m?)?'

    // put them all together
    const locRe = new RegExp(`^${dms}(N|S)\\s+${dms}(E|W)\\s+${alt}`, 'i')
    const r = string.match(locRe)
    if (!r) throw new Error('LOC address: invalid format, see RFC 1876')
    // console.log(r)

    const loc = {
      latitude: {
        degrees   : r[1],
        minutes   : r[2],
        seconds   : r[3],
        hemisphere: r[4].toUpperCase(),
      },
      longitude: {
        degrees   : r[5],
        minutes   : r[6],
        seconds   : r[7],
        hemisphere: r[8].toUpperCase(),
      },
      altitude : r[9],
      size     : r[10],
      precision: {
        horizontal: r[11],
        vertical  : r[12],
      },
    }

    return loc
  }

  /******  IMPORTERS   *******/
  fromTinydns () {
    //
  }

  fromBind () {
    //
  }

  dmsToArcSec (obj) {
    // RFC 1876
    const conv_sec = 1000
    const conv_min = 60 * conv_sec
    const conv_deg = 60 * conv_min

    let retval = (obj.degrees * conv_deg) + ((obj.minutes || 0) * conv_min) + ((obj.seconds || 0) * conv_sec)
    switch (obj.hemisphere.toUpperCase()) {
      case 'W':
      case 'S':
        retval = -retval
        break
    }
    retval += 2**31  // LAT equator or LON prime meridian
    return retval
  }

  toExponent (val) {
    /*
     RFC 1876, ... expressed as a pair of four-bit unsigned
     integers, each ranging from zero to nine, with the most
     significant four bits representing the base and the second
     number representing the power of ten by which to multiply
     the base.
    */
    let exponent = 0
    while (val >= 10) {
      val /= 10
      ++exponent
    }
    return (parseInt(val) << 4) | (exponent & 0x0f)
  }

  /******  EXPORTERS   *******/
  toBind () {
    const fields = [ 'name', 'ttl', 'class', 'type', 'address' ]
    return `${fields.map(f => this.get(f)).join('\t')}\n`
  }

  toTinydns () {
    const loc = this.parseLoc(this.get('address'))

    // LOC format declares in meters, tinydns uses cm (hence * 100)
    let rdata = ''
    rdata += TINYDNS.UInt8toOctal(0)  // version
    rdata += TINYDNS.UInt8toOctal(this.toExponent(loc.size * 100))
    rdata += TINYDNS.UInt8toOctal(this.toExponent(loc.precision.horizontal * 100))
    rdata += TINYDNS.UInt8toOctal(this.toExponent(loc.precision.vertical * 100))
    rdata += TINYDNS.UInt32toOctal(this.dmsToArcSec(loc.latitude))
    rdata += TINYDNS.UInt32toOctal(this.dmsToArcSec(loc.longitude))
    rdata += TINYDNS.UInt32toOctal(loc.altitude * 100 + 100000 * 100)

    return `:${this.get('name')}:29:${rdata}:${this.get('ttl')}::\n`
  }
}

module.exports = LOC
