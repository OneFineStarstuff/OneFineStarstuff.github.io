/**
 * GIEN ESLint trust rules (A1, WP-114). Merge into your existing config, or run standalone:
 *   npx eslint --no-eslintrc -c lint/eslint.gien.cjs "webapp/src/**/*.{ts,tsx}"
 */
module.exports = {
  rules: {
    'no-restricted-properties': [
      'error',
      {
        object: 'Math',
        property: 'random',
        message: 'Use cryptoRandom()/cryptoSeed() from webapp/src/lib/random.ts; Math.random is not deterministic, replayable, or cryptographically seeded.'
      }
    ],
    'no-restricted-syntax': [
      'warn',
      {
        selector: "CallExpression[callee.name='cryptoRandom'][arguments.length>0]",
        message: 'cryptoRandom() takes no arguments; use cryptoSeed(bytes) for keyed seeds.'
      }
    ]
  }
};
