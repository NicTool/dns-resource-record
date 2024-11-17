import globals from 'globals'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import js from '@eslint/js'
import { FlatCompat } from '@eslint/eslintrc'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const compat = new FlatCompat({
  baseDirectory: __dirname,
  recommendedConfig: js.configs.recommended,
  allConfig: js.configs.all,
})

export default [
  {
    languageOptions: {
      ecmaVersion: 'latest',
      globals: {
        ...globals.node,
        ...globals.browser,
        ...globals.mocha,
      },
      sourceType: 'module',
    },

    rules: {
      // 'no-undef': [ 'warn' ],
      'no-unused-vars': [
        'error',
        {
          args: 'none',
        },
      ],

      'dot-notation': 'error',
      'prefer-const': 'warn',
    },
  },
  js.configs.recommended,
]
