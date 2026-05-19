function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function stringProperty(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function primitiveProperty(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  if (typeof value === "string" && value.length > 0) {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return undefined;
}

function nestedMessage(value: unknown): string | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  return (
    stringProperty(value, "message") ??
    stringProperty(value, "errorMessage") ??
    stringProperty(value, "detail")
  );
}

function objectErrorMessage(error: Record<string, unknown>): string {
  const baseMessage =
    stringProperty(error, "message") ??
    stringProperty(error, "errorMessage") ??
    stringProperty(error, "detail") ??
    stringProperty(error, "description") ??
    stringProperty(error, "error") ??
    nestedMessage(error.error) ??
    nestedMessage(error.response);
  const details = [
    ["name", primitiveProperty(error, "name")],
    ["code", primitiveProperty(error, "code")],
    ["status", primitiveProperty(error, "status")],
    ["statusCode", primitiveProperty(error, "statusCode")],
    ["type", primitiveProperty(error, "type")],
  ]
    .filter((entry): entry is [string, string] => entry[1] !== undefined)
    .filter(([, value]) => value !== baseMessage)
    .map(([key, value]) => `${key}=${value}`);

  if (baseMessage) {
    return details.length > 0 ? `${baseMessage} (${details.join(", ")})` : baseMessage;
  }
  if (details.length > 0) {
    return `Non-Error exception (${details.join(", ")})`;
  }
  return "Non-Error exception object";
}

export function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message || error.name || "Unknown error";
  }
  if (typeof error === "string") {
    return error;
  }
  if (
    typeof error === "number" ||
    typeof error === "boolean" ||
    typeof error === "bigint"
  ) {
    return String(error);
  }
  if (error === null) {
    return "Unknown error: null";
  }
  if (error === undefined) {
    return "Unknown error";
  }
  if (isRecord(error)) {
    return objectErrorMessage(error);
  }
  return "Unknown error";
}

export function normalizeError(error: unknown): Error {
  if (error instanceof Error) {
    return error;
  }
  return new Error(errorMessage(error), { cause: error });
}
