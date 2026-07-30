export const API_INTENT_HEADER = "x-planscope-request";
export const API_INTENT_VALUE = "1";

const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const UNTRUSTED_FETCH_SITES = new Set(["cross-site", "same-site"]);

export class RequestSecurityError extends Error {
  constructor(message, options = {}) {
    super(message, options);
    this.name = "RequestSecurityError";
    this.code = options.code ?? "request_rejected";
    this.httpStatus = options.httpStatus ?? 403;
    this.retryAfterSeconds = options.retryAfterSeconds ?? null;
  }
}

export function createRequestSecurity(options = {}) {
  const port = normalizePort(options.port, 4317);
  const trustProxy = options.trustProxy === true;
  const isTrustedProxy =
    typeof options.isTrustedProxy === "function"
      ? options.isTrustedProxy
      : () => trustProxy;
  const publicOrigin = parsePublicOrigin(options.publicOrigin);
  const allowedHosts = new Set([
    `127.0.0.1:${port}`,
    `localhost:${port}`,
    `[::1]:${port}`,
    ...(port === 80 || port === 443
      ? ["127.0.0.1", "localhost", "[::1]"]
      : []),
    ...parseAllowedHosts(options.allowedHosts),
  ]);
  if (publicOrigin) allowedHosts.add(publicOrigin.host.toLowerCase());

  const bindHost = String(options.bindHost ?? "127.0.0.1")
    .trim()
    .toLowerCase();
  if (!isLoopbackBindHost(bindHost)) {
    if (
      (!publicOrigin || publicOrigin.protocol !== "https:") &&
      options.allowInsecurePublicOrigin !== true
    ) {
      throw new RequestSecurityError(
        "监听非本机地址时必须配置 HTTPS 的 PUBLIC_ORIGIN。",
        {
          code: "unsafe_public_binding",
          httpStatus: 500,
        },
      );
    }
    if (
      !publicOrigin &&
      parseAllowedHosts(options.allowedHosts).length === 0
    ) {
      throw new RequestSecurityError(
        "监听非本机地址时必须配置可信 Host。",
        {
          code: "unsafe_public_binding",
          httpStatus: 500,
        },
      );
    }
  }

  const guard = (request, pathname) => {
    const host = normalizeRequestHost(request.headers?.host);
    if (!host || !allowedHosts.has(host)) {
      throw new RequestSecurityError(
        "请求 Host 未被当前服务允许。",
        {
          code: "misdirected_request",
          httpStatus: 421,
        },
      );
    }

    const secureTransport = requestIsSecure(
      request,
      isTrustedProxy(request),
    );
    if (
      publicOrigin?.protocol === "https:" &&
      !secureTransport
    ) {
      throw new RequestSecurityError(
        "公网访问必须通过 HTTPS。",
        {
          code: "https_required",
          httpStatus: 426,
        },
      );
    }

    if (!String(pathname).startsWith("/api/")) return;

    const fetchSite = headerValue(
      request.headers?.["sec-fetch-site"],
    ).toLowerCase();
    if (UNTRUSTED_FETCH_SITES.has(fetchSite)) {
      throw new RequestSecurityError("已拒绝跨站 API 请求。", {
        code: "cross_site_request_blocked",
        httpStatus: 403,
      });
    }

    const method = String(request.method ?? "GET").toUpperCase();
    if (!UNSAFE_METHODS.has(method)) return;

    if (
      headerValue(request.headers?.[API_INTENT_HEADER]) !==
      API_INTENT_VALUE
    ) {
      throw new RequestSecurityError(
        "请求缺少同源操作标识。",
        {
          code: "api_intent_required",
          httpStatus: 403,
        },
      );
    }

    const origin = headerValue(request.headers?.origin);
    if (!origin) return;
    const expectedOrigin =
      publicOrigin?.origin ??
      `${secureTransport ? "https" : "http"}://${host}`;
    if (normalizeOrigin(origin) !== expectedOrigin) {
      throw new RequestSecurityError("请求来源与当前站点不一致。", {
        code: "origin_mismatch",
        httpStatus: 403,
      });
    }
  };

  guard.allowedHosts = Object.freeze([...allowedHosts]);
  guard.publicOrigin = publicOrigin?.origin ?? null;
  return guard;
}

export function assertJsonRequest(request) {
  const contentType = headerValue(
    request.headers?.["content-type"],
  )
    .split(";")[0]
    .trim()
    .toLowerCase();
  if (contentType !== "application/json") {
    throw new RequestSecurityError(
      "该接口只接受 application/json 请求。",
      {
        code: "unsupported_media_type",
        httpStatus: 415,
      },
    );
  }
}

export function assertEmptyRequest(request) {
  const contentLength = Number(
    request.headers?.["content-length"] ?? 0,
  );
  const transferEncoding = headerValue(
    request.headers?.["transfer-encoding"],
  );
  if (
    (Number.isFinite(contentLength) && contentLength > 0) ||
    transferEncoding
  ) {
    throw new RequestSecurityError(
      "该接口不接受请求内容。",
      {
        code: "unexpected_request_body",
        httpStatus: 413,
      },
    );
  }
}

export function requestIsSecure(request, trustProxy = false) {
  if (request.socket?.encrypted) return true;
  if (!trustProxy) return false;
  return (
    headerValue(request.headers?.["x-forwarded-proto"])
      .split(",")[0]
      .trim()
      .toLowerCase() === "https"
  );
}

export function securityResponseHeaders({ secure = false } = {}) {
  const headers = {
    "Cache-Control": "no-store",
    "Content-Security-Policy":
      "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-src 'none'; frame-ancestors 'none'; object-src 'none'; manifest-src 'none'; media-src 'none'; worker-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Origin-Agent-Cluster": "?1",
    "Permissions-Policy":
      "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), usb=()",
    "Referrer-Policy": "no-referrer",
    Vary: "Sec-Fetch-Site, Origin",
    "X-Content-Type-Options": "nosniff",
    "X-DNS-Prefetch-Control": "off",
    "X-Frame-Options": "DENY",
    "X-Permitted-Cross-Domain-Policies": "none",
  };
  if (secure) {
    headers["Strict-Transport-Security"] =
      "max-age=31536000";
  }
  return headers;
}

function parsePublicOrigin(value) {
  const source = String(value ?? "").trim();
  if (!source) return null;

  let url;
  try {
    url = new URL(source);
  } catch {
    throw new RequestSecurityError("PUBLIC_ORIGIN 格式无效。", {
      code: "invalid_public_origin",
      httpStatus: 500,
    });
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    (url.pathname !== "/" && url.pathname !== "") ||
    url.search ||
    url.hash
  ) {
    throw new RequestSecurityError(
      "PUBLIC_ORIGIN 必须是没有路径、查询或凭据的 HTTP(S) Origin。",
      {
        code: "invalid_public_origin",
        httpStatus: 500,
      },
    );
  }
  return url;
}

function parseAllowedHosts(value) {
  const values = Array.isArray(value)
    ? value
    : String(value ?? "").split(",");
  return [
    ...new Set(
      values
        .map(normalizeRequestHost)
        .filter(Boolean),
    ),
  ];
}

function normalizeRequestHost(value) {
  const host = headerValue(value).trim().toLowerCase();
  if (
    !host ||
    host.length > 255 ||
    /[\u0000-\u0020\u007f,/@\\]/.test(host)
  ) {
    return "";
  }
  return host;
}

function normalizeOrigin(value) {
  try {
    return new URL(String(value)).origin;
  } catch {
    return "";
  }
}

function headerValue(value) {
  return Array.isArray(value)
    ? String(value[0] ?? "")
    : String(value ?? "");
}

function normalizePort(value, fallback) {
  const port = Number(value);
  return Number.isInteger(port) && port >= 1 && port <= 65_535
    ? port
    : fallback;
}

function isLoopbackBindHost(value) {
  return ["127.0.0.1", "::1", "localhost"].includes(value);
}
