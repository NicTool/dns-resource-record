import RR from '../rr.js'

const REF = {
  // RFC 1876
  LATLON: 2 ** 31, // LAT equator, LON prime meridian
  ALTITUDE: 100000 * 100, // reference spheroid used by GPS, in cm
}

const CONV = {
  sec: 1000,
  min: 60 * 1000,
  deg: 60 * 60 * 1000,
}

export default class LOC extends RR {
  static typeName = 'LOC'
  static typeId = 29
  static RFCs = [1876]
  static rdataFields = [['address', 'list']]

  constructor(opts) {
    super(opts)
  }

  /****** Resource record specific setters   *******/
  setAddress(val) {
    if (!val) this.throwHelp('LOC: address is required')

    /*
    ... LOC ( d1 [m1 [s1]] {"N"|"S"} d2 [m2 [s2]]
             {"E"|"W"} alt["m"] [siz["m"] [hp["m"]
             [vp["m"]]]] )
    */
    this.parseLoc(val)

    this.set('address', val)
  }

  getDescription() {
    return 'Location'
  }

  getCanonical() {
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'LOC',
      address: '52 22 23.000 N 4 53 32.000 E 10m 100m 10m 2m',
    }
  }

  parseLoc(string) {
    // d1 [m1 [s1]]
    const dms = '(\\d+)\\s+(?:(\\d+)\\s+)?(?:([\\d.]+)\\s+)?'

    // alt["m"] [siz["m"] [hp["m"] [vp["m"]]]]
    const alt = '(-?[\\d.]+)m?(?:\\s+([\\d.]+)m?)?(?:\\s+([\\d.]+)m?)?(?:\\s+([\\d.]+)m?)?'

    // put them all together
    const locRe = new RegExp(`^${dms}(N|S)\\s+${dms}(E|W)\\s+${alt}$`, 'i')
    const r = string.match(locRe)
    if (!r) this.throwHelp('LOC address: invalid format, see RFC 1876')

    const loc = {
      latitude: {
        degrees: r[1],
        minutes: r[2],
        seconds: r[3],
        hemisphere: r[4].toUpperCase(),
      },
      longitude: {
        degrees: r[5],
        minutes: r[6],
        seconds: r[7],
        hemisphere: r[8].toUpperCase(),
      },
      altitude: Math.round(r[9] * 100), // m -> cm
      size: (r[10] ?? DEFAULT_CM[0] / 100) * 100,
      precision: {
        horizontal: (r[11] ?? DEFAULT_CM[1] / 100) * 100,
        vertical: (r[12] ?? DEFAULT_CM[2] / 100) * 100,
      },
    }

    // RFC 1876 §3
    const { latitude: lat, longitude: lon } = loc
    if (lat.degrees > 90 || lon.degrees > 180 || [lat, lon].some((l) => l.minutes >= 60 || l.seconds >= 60))
      this.throwHelp(`LOC address: latitude or longitude out of range: ${string}`)
    if (loc.altitude < -REF.ALTITUDE || loc.altitude + REF.ALTITUDE > 0xffffffff)
      this.throwHelp(`LOC address: altitude out of range: ${string}`)
    return loc
  }

  /******  IMPORTERS   *******/

  dmsToArcSec(obj) {
    // rounded, since decimal seconds such as 32.123 are inexact in binary
    let retval = Math.round(
      obj.degrees * CONV.deg + (obj.minutes ?? 0) * CONV.min + (obj.seconds ?? 0) * CONV.sec,
    )
    switch (obj.hemisphere.toUpperCase()) {
      case 'W':
      case 'S':
        retval = -retval
        break
    }
    retval += REF.LATLON
    return retval
  }

  arcSecToDMS(rawmsec, latlon) {
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
        this.throwHelp('unknown or missing hemisphere')
    }

    return `${deg} ${min} ${sec}${msec ? `.${String(msec).padStart(3, '0')}` : ''} ${hem}`
  }

  fromExponent(prec) {
    const mantissa = ((prec >> 4) & 0x0f) % 10
    const exponent = ((prec >> 0) & 0x0f) % 10
    return mantissa * Math.pow(10, exponent)
  }

  toExponent(val) {
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

  toHuman(obj) {
    const optional = [obj.size, obj.precision.horizontal, obj.precision.vertical]
    while (optional.length && optional.at(-1) === DEFAULT_CM[optional.length - 1]) optional.pop()
    return [
      `${obj.latitude} ${obj.longitude} ${obj.altitude / 100}m`,
      ...optional.map((cm) => `${cm / 100}m`),
    ].join(' ')
  }

  fromWire({ owner, cls, ttl, rdata }) {
    // RFC 1876 §2: version 0 is the only format, 16 octets long
    if (rdata.length !== 16 || rdata[0] !== 0) throw new Error('LOC: rdata is not version 0, 16 bytes')
    const dv = new DataView(rdata.buffer, rdata.byteOffset)
    const l = {
      size: this.fromExponent(rdata[1]),
      precision: {
        horizontal: this.fromExponent(rdata[2]),
        vertical: this.fromExponent(rdata[3]),
      },
      latitude: this.arcSecToDMS(dv.getUint32(4), 'lat'),
      longitude: this.arcSecToDMS(dv.getUint32(8), 'lon'),
      altitude: dv.getUint32(12) - REF.ALTITUDE,
    }
    return new LOC({
      owner,
      ttl,
      class: cls,
      type: 'LOC',
      address: this.toHuman(l),
    })
  }

  /******  EXPORTERS   *******/

  getWireRdata() {
    const loc = this.parseLoc(this.get('address'))
    const bytes = new Uint8Array(16)
    const dv = new DataView(bytes.buffer, bytes.byteOffset)

    bytes[0] = 0 // version
    bytes[1] = this.toExponent(loc.size)
    bytes[2] = this.toExponent(loc.precision.horizontal)
    bytes[3] = this.toExponent(loc.precision.vertical)
    dv.setUint32(4, this.dmsToArcSec(loc.latitude))
    dv.setUint32(8, this.dmsToArcSec(loc.longitude))
    dv.setUint32(12, loc.altitude + REF.ALTITUDE)

    return bytes
  }
}

// RFC 1876 §2: omitted size, horizontal and vertical precision are 1m, 10000m and 10m.
const DEFAULT_CM = [100, 1000000, 1000]
