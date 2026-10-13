// Runs describe() bodies, where the test files call base.valid(), and skips the tests.
const noop = () => {}

export function describe(name, options, fn) {
  ;(typeof options === 'function' ? options : fn)?.()
}

export const suite = describe
export const it = noop
export const test = noop
export const before = noop
export const after = noop
export const beforeEach = noop
export const afterEach = noop
export default noop
