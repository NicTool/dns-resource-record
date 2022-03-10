
const RR      = require('./index').RR
const TINYDNS = require('../lib/tinydns')

const REF = {  // RFC 1876
  LATLON  : 2**31,  // LAT equator, LON prime meridian
  ALTITUDE: 100000 * 100, // reference spheroid used by GPS, in cm
}

const CONV = {
  sec: 1000,
  min: 60 * 1000,
  deg: 60 * 60 * 1000,
}

class LOC extends RR {
  constructor (opts) {
    super(opts)
    if (opts === null) return

    if (opts.tinyline) return this.fromTinydns(opts.tinyline)
    if (opts.bindline) return this.fromBind(opts.bindline)

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

  getDescription () {
    return 'Location'
  }

  getRdataFields (arg) {
    return [ 'address' ]
  }

  getRFCs () {
    return [ 1876 ]
  }

  getTypeId () {
    return 29
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
      altitude : r[9] * 100,  // m -> cm
      size     : r[10] * 100,
      precision: {
        horizontal: r[11] * 100,
        vertical  : r[12] * 100,
      },
    }

    return loc
  }

  /******  IMPORTERS   *******/
  fromTinydns (str) {
    // LOC via generic, :fqdn:n:rdata:ttl:timestamp:lo
    const [ fqdn, n, rdata, ttl, ts, loc ] = str.substring(1).split(':')
    if (n != 29) throw new Error('LOC fromTinydns, invalid n')

    // divide by 100 is to convert cm to meters
    const l = {
      version  : TINYDNS.octalToUInt8(rdata.substring(0, 4)),
      size     : this.fromExponent(TINYDNS.octalToUInt8(rdata.substring(4, 8))),
      precision: {
        horizontal: this.fromExponent(TINYDNS.octalToUInt8(rdata.substring( 8, 12))),
        vertical  : this.fromExponent(TINYDNS.octalToUInt8(rdata.substring(12, 16))),
      },
      latitude : this.arcSecToDMS(TINYDNS.octalToUInt32(rdata.substring(16, 32)), 'lat'),
      longitude: this.arcSecToDMS(TINYDNS.octalToUInt32(rdata.substring(32, 48)), 'lon'),
      altitude : TINYDNS.octalToUInt32(rdata.substring(48, 64)) - REF.ALTITUDE,
    }

    return new this.constructor({
      type     : 'LOC',
      name     : fqdn,
      address  : this.toHuman(l),
      ttl      : parseInt(ttl, 10),
      timestamp: ts,
      location : loc !== '' && loc !== '\n' ? loc : '',
    })
  }

  fromBind (str) {
    const [ fqdn, ttl, c, type ] = str.split(/\s+/)

    return new this.constructor({
      class  : c,
      type   : type,
      name   : fqdn,
      address: str.split(/\s+/).slice(4).join(' ').trim(),
      ttl    : parseInt(ttl, 10),
    })
  }

  dmsToArcSec (obj) {
    let retval = (obj.degrees * CONV.deg) + ((obj.minutes || 0) * CONV.min) + ((obj.seconds || 0) * CONV.sec)
    switch (obj.hemisphere.toUpperCase()) {
      case 'W':
      case 'S':
        retval = -retval
        break
    }
    retval += REF.LATLON
    return retval
  }

  arcSecToDMS (rawmsec, latlon) {
    let msec = Math.abs(rawmsec - REF.LATLON)
    // console.log(`rawmsec: ${rawmsec}, abs msec: ${msec}`)

    const deg = Math.floor(msec / CONV.deg)
    msec -= deg * CONV.deg

    const min = Math.floor(msec / CONV.min)
    msec -= min * CONV.min

    const sec = Math.floor(msec / CONV.sec)
    msec -= sec * CONV.sec

    let hem
    switch (latlon) {
      case 'lat':
        hem = rawmsec >= REF.LATLON ? 'N' : 'S'
        break
      case 'lon':
        hem = rawmsec >= REF.LATLON ? 'E' : 'W'
        break
      default:
        throw new Error('unknown or missing hemisphere')
    }

    return `${deg} ${min} ${sec}${msec ? '.'+msec : ''} ${hem}`
  }

  fromExponent (prec) {
    const mantissa = ((prec >> 4) & 0x0f) % 10
    const exponent = ((prec >> 0) & 0x0f) % 10
    return mantissa * Math.pow(10, exponent)
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

  toHuman (obj) {
    let r = `${obj.latitude} ${obj.longitude} ${(obj.altitude/100)}m`
    if (obj.size)                 r += ` ${obj.size/100}m`
    if (obj.precision.horizontal) r += ` ${obj.precision.horizontal / 100}m`
    if (obj.precision.vertical  ) r += ` ${obj.precision.vertical / 100}m`
    return r
  }

  /******  EXPORTERS   *******/

  toTinydns () {
    const loc = this.parseLoc(this.get('address'))

    // LOC format declares in meters, tinydns uses cm (hence * 100)
    let rdata = ''
    rdata += TINYDNS.UInt8toOctal(0)  // version
    rdata += TINYDNS.UInt8toOctal(this.toExponent(loc.size))
    rdata += TINYDNS.UInt8toOctal(this.toExponent(loc.precision.horizontal))
    rdata += TINYDNS.UInt8toOctal(this.toExponent(loc.precision.vertical))
    rdata += TINYDNS.UInt32toOctal(this.dmsToArcSec(loc.latitude))
    rdata += TINYDNS.UInt32toOctal(this.dmsToArcSec(loc.longitude))
    rdata += TINYDNS.UInt32toOctal(loc.altitude + REF.ALTITUDE)

    return `:${this.get('name')}:29:${rdata}:${this.get('ttl')}::\n`
  }
}

module.exports = LOC
