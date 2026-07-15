/** Internal helpers — the package has zero runtime dependencies by design */

export const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);

export const mapEntries = (
  record: Record<string, unknown>,
  fn: (value: unknown, key: string) => unknown,
): Record<string, unknown> => Object.fromEntries(Object.entries(record).map(([key, value]) => [key, fn(value, key)]));
