import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    'jwt/index': 'src/jwt/index.ts',
    'password/index': 'src/password/index.ts',
    'ratelimit/index': 'src/ratelimit/index.ts',
    'rbac/index': 'src/rbac/index.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  target: 'es2022',
});
