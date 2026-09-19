/**
 * Chunk size for createMany() calls on the affected-package/product tables.
 *
 * Postgres caps a single statement at 65,535 bind parameters, and createMany
 * binds one per column per row -- so the real ceiling is roughly
 * 65535 / (column count), which for the widest of these tables
 * (NVDAffectedPackage, 14 columns) is about 4,600 rows. Importing one record
 * whose affected list exceeded that would fail outright, where the previous
 * one-insert-per-row loop simply took a long time.
 *
 * 1,000 keeps every table well clear of its own ceiling with room for columns
 * to be added later, and is still ~1,000x fewer round trips than per-row
 * inserts. It also bounds how long a single statement holds its locks inside
 * the surrounding interactive transaction, which Prisma times out at 5s by
 * default.
 */
export const BULK_INSERT_CHUNK_SIZE = 1000;

/**
 * Run `insert` over `rows` in chunks sized for the parameter limit above.
 * Does nothing when there is nothing to insert.
 */
export async function createManyChunked<T>(
  rows: T[],
  insert: (chunk: T[]) => Promise<unknown>,
): Promise<void> {
  for (let i = 0; i < rows.length; i += BULK_INSERT_CHUNK_SIZE) {
    await insert(rows.slice(i, i + BULK_INSERT_CHUNK_SIZE));
  }
}
