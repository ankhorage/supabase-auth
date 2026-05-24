import { defineParadoxConfig } from '@ankhorage/paradox';

export default defineParadoxConfig({
  mode: 'write',

  docs: {
    title: 'SUPABASE AUTH',
  },

  package: {
    entrypoints: ['src/index.ts'],
  },

  output: {
    dir: 'paradox',
  },
});
