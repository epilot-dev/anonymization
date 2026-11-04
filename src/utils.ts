/** Internal helpers — the package has zero runtime dependencies by design */

export const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);

  return proto === Object.prototype || proto === null;
};

/** assign without invoking the `__proto__` setter for a JSON-parsed own `__proto__` key */
const setOwn = (target: Record<string, unknown>, key: string, value: unknown) => {
  if (key === '__proto__') {
    Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
  } else {
    target[key] = value;
  }
};

/** New object with fn applied to every own enumerable value (key order preserved) */
export const mapEntries = (
  record: Record<string, unknown>,
  fn: (value: unknown, key: string) => unknown,
): Record<string, unknown> => {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(record)) {
    setOwn(out, key, fn(record[key], key));
  }

  return out;
};

/**
 * Like mapEntries, but returns the input itself when fn changed no value, so unchanged
 * subtrees of large responses are not copied. Callers must not mutate the result.
 */
export const mapEntriesShared = (
  record: Record<string, unknown>,
  fn: (value: unknown, key: string) => unknown,
): Record<string, unknown> => {
  const keys = Object.keys(record);
  let out: Record<string, unknown> | undefined;
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    const value = record[key];
    const mapped = fn(value, key);
    if (out) {
      setOwn(out, key, mapped);
    } else if (mapped !== value) {
      out = {};
      for (let j = 0; j < i; j++) setOwn(out, keys[j], record[keys[j]]);
      setOwn(out, key, mapped);
    }
  }

  return out ?? record;
};

/** Like Array.prototype.map, but returns the input itself when fn changed no item */
export const mapArrayShared = <T>(items: T[], fn: (item: T) => T): T[] => {
  let out: T[] | undefined;
  for (let i = 0; i < items.length; i++) {
    const mapped = fn(items[i]);
    if (out) {
      out.push(mapped);
    } else if (mapped !== items[i]) {
      out = items.slice(0, i);
      out.push(mapped);
    }
  }

  return out ?? items;
};
