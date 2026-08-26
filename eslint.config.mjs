import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist'] },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      // Underscore-prefixed args/vars are the existing convention in this
      // codebase for intentionally-unused parameters (e.g. Fastify's `_req`).
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },
);
