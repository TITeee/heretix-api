import { describe, it, expect, vi } from 'vitest';
import { createManyChunked, BULK_INSERT_CHUNK_SIZE } from './bulk-insert.js';

describe('createManyChunked', () => {
  it('does not call the insert at all for an empty list', async () => {
    const insert = vi.fn();
    await createManyChunked([], insert);
    expect(insert).not.toHaveBeenCalled();
  });

  it('sends a single chunk when the rows fit', async () => {
    const insert = vi.fn().mockResolvedValue(undefined);
    const rows = Array.from({ length: 10 }, (_, i) => i);

    await createManyChunked(rows, insert);

    expect(insert).toHaveBeenCalledTimes(1);
    expect(insert).toHaveBeenCalledWith(rows);
  });

  it('splits past the chunk size, covering every row exactly once', async () => {
    // The ceiling this guards is Postgres' 65,535 bind parameters: one real
    // record (CVE-2016-1409) already carries 4,891 affected-package rows,
    // which at 14 columns per row would exceed it in a single statement.
    const insert = vi.fn().mockResolvedValue(undefined);
    const rows = Array.from({ length: BULK_INSERT_CHUNK_SIZE * 2 + 37 }, (_, i) => i);

    await createManyChunked(rows, insert);

    expect(insert).toHaveBeenCalledTimes(3);
    const chunks = insert.mock.calls.map(c => c[0] as number[]);
    expect(chunks.map(c => c.length)).toEqual([BULK_INSERT_CHUNK_SIZE, BULK_INSERT_CHUNK_SIZE, 37]);
    expect(chunks.flat()).toEqual(rows);
  });

  it('stops at the first failing chunk rather than continuing', async () => {
    // Each call runs inside the caller's transaction, so a mid-way failure has
    // to abort rather than leave a partially written set behind.
    const insert = vi.fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error('too many parameters'));
    const rows = Array.from({ length: BULK_INSERT_CHUNK_SIZE * 3 }, (_, i) => i);

    await expect(createManyChunked(rows, insert)).rejects.toThrow('too many parameters');
    expect(insert).toHaveBeenCalledTimes(2);
  });
});
