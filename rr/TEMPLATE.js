import RR from '../rr.js'

/**
 * DNS Resource Record Template
 *
 * Use this as a starting point for creating a new Resource Record (RR) class.
 * Replace 'TEMPLATE' with the actual record type (e.g., 'MX', 'SRV').
 *
 * ## Mandates
 * - Every new RR MUST extend the `RR` class.
 * - 100% test coverage is required for all new PRs.
 * - Follow established patterns for naming and implementation.
 * - **Registration**: You MUST update `index.js` to import and export the new class and add it to the `classes` array.
 * - **Tests**: You MUST create a corresponding test file in `test/rr/<type>.js` (mirroring an existing test file like `test/rr/a.js`).
 *
 * ## `rdataFields` and Avoiding Boilerplate
 * The `rdataFields` static property defines the fields in the RDATA section.
 * It is an array where each element can be:
 *   - A string: The field name.
 *   - An array: `[fieldName, type]`
 *
 * Supported types for `setTypedValue`:
 *   - `u8`, `u16`, `u32`: Unsigned integers of 8, 16, or 32 bits.
 *   - `fqdn`: A fully qualified domain name.
 *   - `qstr`: Quoted string field (BIND quoting behavior).
 *   - `charstr`: DNS length-prefixed character-string (max 255 bytes).
 *   - `qcharstr`: Quoted DNS length-prefixed character-string.
 *   - `charstrs`: Concatenated DNS character-strings.
 *   - `svcparams`: SVCB/HTTPS params string.
 *   - `base64`: Base64 encoded data.
 *   - `hex`: Hexadecimal encoded data.
 *   - `str`: A simple string.
 *   - `ipv4`: An IPv4 address.
 *   - `ipv6`: An IPv6 address.
 *
 * If you provide a type in `rdataFields`, the base `RR` class automatically
 * handles validation and setting of that field. You only need to implement
 * a custom `set<FieldName>` method if you need more complex validation
 * logic than what the default types provide.
 */

export default class TEMPLATE extends RR {
  // The DNS record type name (e.g., 'A', 'MX', 'TXT')
  static typeName = 'TEMPLATE'
  static typeId = 0
  static RFCs = []
  static tags = []

  // The tinydns line type, for types with a native line. Without one, records
  // take the generic `:` line, encoded and decoded through the wire format.
  static tinydnsType = 'T'

  // Define the RDATA fields.
  // Using types here avoids the need for manual setters in many cases.
  static rdataFields = [
    ['field1', 'u16'],
    ['field2', 'fqdn'],
  ]

  /****** Resource record specific setters   *******/

  /*
  // Example of a custom setter. Only implement if default validation
  // from `rdataFields` is insufficient.
  setField1(val) {
    if (val === undefined) val = this?.default?.field1
    if (val === undefined) this.throwHelp('TEMPLATE: field1 is required')
    this.is16bitInt('TEMPLATE', 'field1', val)
    this.set('field1', parseInt(val, 10))
  }
  */

  /****** Metadata (Required) *******/

  getDescription() {
    return 'Short description of the TEMPLATE record'
  }

  getCanonical() {
    // Returns a sample object representing a valid record.
    // This is used for documentation and testing.
    return {
      owner: 'example.com.',
      ttl: 3600,
      class: 'IN',
      type: 'TEMPLATE',
      field1: 10,
      field2: 'target.example.com.',
    }
  }

  /******  IMPORTERS / EXPORTERS (Recommended) *******/

  /*
  // Only for a native tinydns line; generic `:` lines need no code.
  fromTinydns({ tinyline }) {
     // Implementation...
  }
  */

  /*
  // Wire format comes from the rdataFields types in both directions. Override
  // getWireRdata() and fromWire() only for rdata those types can't describe.
  getWireRdata() {
    // Returns a Uint8Array.
  }
  */
}
