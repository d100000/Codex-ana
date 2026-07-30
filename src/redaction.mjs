const DEFAULT_MAX_LENGTH = 4_096;
const REDACTED = "[REDACTED]";

export function redactSensitiveText(value, secrets = []) {
  let result = String(value ?? "");

  for (const secret of Array.isArray(secrets) ? secrets : []) {
    const candidate = String(secret ?? "");
    if (candidate.length < 4) continue;
    for (const variant of new Set([
      candidate,
      encodeURIComponent(candidate),
    ])) {
      result = result.replaceAll(variant, REDACTED);
    }
  }

  result = result
    .replace(
      /\b(Bearer)\s+[A-Za-z0-9._~+/=-]{8,}/gi,
      `$1 ${REDACTED}`,
    )
    .replace(/\bsk-[A-Za-z0-9][A-Za-z0-9._-]{7,}\b/g, REDACTED)
    .replace(
      /(["']?(?:api[-_]?key|authorization|proxy-authorization|access[-_]?token|refresh[-_]?token|token|secret|password|cookie|set-cookie)["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|Bearer\s+[^\s,;}]+|[^\s,;}]+)/gi,
      (_match, prefix, sensitiveValue) => {
        const quote = sensitiveValue[0];
        return quote === '"' || quote === "'"
          ? `${prefix}${quote}${REDACTED}${quote}`
          : `${prefix}${REDACTED}`;
      },
    )
    .replace(
      /([?&](?:api[-_]?key|access[-_]?token|token|secret|password)=)[^&\s]+/gi,
      `$1${REDACTED}`,
    );

  return result;
}

export function sanitizeDiagnosticText(value, options = {}) {
  const maxLength = clampMaxLength(options.maxLength);
  const redacted = redactSensitiveText(value, options.secrets);
  const clean = redacted
    .replace(/\r\n?/g, "\n")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ")
    .trim();
  return clean.slice(0, maxLength);
}

export function createDiagnosticExcerpt(value, options = {}) {
  const maxLength = clampMaxLength(options.maxLength);
  const redacted = redactSensitiveText(value, options.secrets);
  const clean = redacted
    .replace(/\r\n?/g, "\n")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ")
    .trim();
  return {
    text: clean.slice(0, maxLength),
    truncated: clean.length > maxLength,
  };
}

function clampMaxLength(value) {
  const length = Number(value);
  return Number.isInteger(length) && length > 0 && length <= 65_536
    ? length
    : DEFAULT_MAX_LENGTH;
}
