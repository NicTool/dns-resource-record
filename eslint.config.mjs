import globals from 'globals'
import js from '@eslint/js'
import { defineConfig } from 'eslint/config'

export default defineConfig([
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
])
