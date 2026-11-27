export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Non-finite numbers are not canonical JSON values.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${keys.map((key) => {
      if (record[key] === undefined) throw new Error(`Undefined is not permitted in canonical JSON: ${key}`);
      return `${JSON.stringify(key)}:${canonicalJson(record[key])}`;
    }).join(",")}}`;
  }
  throw new Error(`Unsupported canonical JSON type: ${typeof value}`);
}
