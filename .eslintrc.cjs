// @ts-check
/** @type {import('@typescript-eslint/utils').TSESLint.FlatConfig.ConfigArray} */

module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint'],
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
    project: './tsconfig.json',
  },
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:@typescript-eslint/recommended-requiring-type-checking',
  ],
  rules: {
    // Enforce return types for public functions
    '@typescript-eslint/explicit-module-boundary-types': 'warn',

    // Prefer const
    'prefer-const': 'error',

    // No any
    '@typescript-eslint/no-explicit-any': 'error',

    // No floating promises
    '@typescript-eslint/no-floating-promises': 'error',

    // No unused vars
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],

    // No unsafe assignments
    '@typescript-eslint/no-unsafe-assignment': 'error',
    '@typescript-eslint/no-unsafe-call': 'error',
    '@typescript-eslint/no-unsafe-member-access': 'error',

    // Require await in async functions
    '@typescript-eslint/require-await': 'warn',

    // No eval
    'no-eval': 'error',

    // Consistent error handling
    '@typescript-eslint/prefer-promise-reject-errors': 'warn',
  },
  overrides: [
    {
      // Relax rules for test files
      files: ['tests/**/*.ts'],
      rules: {
        '@typescript-eslint/no-explicit-any': 'off',
        '@typescript-eslint/no-unsafe-assignment': 'off',
        '@typescript-eslint/no-unsafe-member-access': 'off',
        '@typescript-eslint/no-unsafe-call': 'off',
      },
    },
  ],
  ignorePatterns: ['dist/', 'node_modules/', '*.js', '*.cjs', 'examples/'],
};
