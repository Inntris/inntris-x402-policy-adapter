/** Isolated RFC 8785 input guard; production canonicalBytes remains unchanged. */
function unicode(value: string): void {
  if (!value.isWellFormed()) throw new TypeError("Lone Unicode surrogate is not JCS input");
}

export function assertJsonValue(value: unknown, forbidExpected = true, depth = 0): void {
  if (depth > 100) throw new TypeError("Input nesting exceeds the safety limit");
  if (typeof value === "string") return unicode(value);
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number" && Number.isFinite(value)) return;
  if (Array.isArray(value)) {
    for (const item of value) assertJsonValue(item, forbidExpected, depth + 1);
    return;
  }
  if (typeof value !== "object" || value === null) throw new TypeError("Not a JSON value");
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null)
    throw new TypeError("Not a JSON object");
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") throw new TypeError("Not a JSON member name");
    unicode(key);
    if (forbidExpected && key === "expected")
      throw new TypeError("Evaluator input must not contain expected");
    if (["__proto__", "constructor", "prototype"].includes(key))
      throw new TypeError(`Unsafe object key: ${key}`);
    const property = Object.getOwnPropertyDescriptor(value, key);
    if (property === undefined || !property.enumerable || !("value" in property))
      throw new TypeError("Not a JSON data member");
    assertJsonValue(property.value, forbidExpected, depth + 1);
  }
}

/** Parse object member names before constructing objects, so duplicates cannot disappear. */
export function parseStrictJson(text: string, forbidExpected = true): unknown {
  let at = 0;
  const whitespace = (): void => {
    while (/[\x20\t\r\n]/u.test(text[at] ?? "!")) at++;
  };
  const error = (): never => {
    throw new TypeError(`Invalid JSON at offset ${at}`);
  };
  const string = (): string => {
    const start = at++;
    while (at < text.length) {
      const character = text[at++];
      if (character === "\\") at++;
      else if (character === '"') {
        // Scalar parsing cannot erase object member names. JSON.parse checks escapes/control bytes.
        const value: unknown = JSON.parse(text.slice(start, at));
        if (typeof value !== "string") return error();
        unicode(value);
        return value;
      }
    }
    return error();
  };
  const parse = (depth: number): unknown => {
    if (depth > 100) throw new TypeError("Input nesting exceeds the safety limit");
    whitespace();
    if (text[at] === '"') return string();
    if (text[at] === "{") {
      at++;
      const object: Record<string, unknown> = {};
      const names = new Set<string>();
      whitespace();
      if (text[at] === "}") {
        at++;
        return object;
      }
      while (at < text.length) {
        whitespace();
        if (text[at] !== '"') return error();
        const name = string();
        if (names.has(name)) throw new TypeError(`Duplicate JSON member: ${name}`);
        names.add(name);
        whitespace();
        if (text[at++] !== ":") return error();
        const value = parse(depth + 1);
        Object.defineProperty(object, name, {
          value,
          enumerable: true,
          writable: true,
          configurable: true,
        });
        whitespace();
        const next = text[at++];
        if (next === "}") return object;
        if (next !== ",") return error();
      }
      return error();
    }
    if (text[at] === "[") {
      at++;
      const array: unknown[] = [];
      whitespace();
      if (text[at] === "]") {
        at++;
        return array;
      }
      while (at < text.length) {
        array.push(parse(depth + 1));
        whitespace();
        const next = text[at++];
        if (next === "]") return array;
        if (next !== ",") return error();
      }
      return error();
    }
    for (const [literal, value] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ] as const) {
      if (text.startsWith(literal, at)) {
        at += literal.length;
        return value;
      }
    }
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(text.slice(at));
    if (match === null) return error();
    at += match[0].length;
    const number = Number(match[0]);
    if (!Number.isFinite(number)) return error();
    return number;
  };
  const value = parse(0);
  whitespace();
  if (at !== text.length) return error();
  assertJsonValue(value, forbidExpected);
  return value;
}
