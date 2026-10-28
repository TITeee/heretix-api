import { z } from 'zod';

/**
 * Text a client sends, bounded so that a request cannot make the server hold and
 * compare huge strings: real names and versions are far shorter (npm's longest
 * package name is 214). A NUL is refused here because Postgres refuses it in text,
 * which reached the client as a 500.
 */
export const clientText = (max: number) =>
  z.string().max(max).refine((s) => !s.includes('\0'), 'must not contain a NUL character');
