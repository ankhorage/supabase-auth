import { readFile, writeFile } from 'node:fs/promises';

const path = 'src/createSupabaseAuthAdapter.ts';
const source = await readFile(path, 'utf8');
const search = `            if (error !== null) throw error;`;
const count = source.split(search).length - 1;
if (count !== 1) {
  throw new Error(`Expected one persistence throw, found ${count}.`);
}
await writeFile(path, source.replace(search, `            if (error !== null) throw new Error(error.message);`));
