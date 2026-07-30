import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP } from "node:net";

const DEFAULT_MAX_REQUEST_BYTES = 64 * 1_024;
const DEFAULT_MAX_RESPONSE_BYTES = 512 * 1_024;
const DEFAULT_MAX_RESPONSE_HEADER_BYTES = 32 * 1_024;
const DEFAULT_DNS_CACHE_MS = 30_000;
const DEFAULT_DNS_TIMEOUT_MS = 5_000;

const PROTECTED_NETWORKS = createProtectedNetworkList();

export class UpstreamSecurityError extends Error {
  constructor(message, options = {}) {
    super(message, options);
    this.name = "UpstreamSecurityError";
    this.code = options.code ?? "unsafe_upstream";
    this.retryable = options.retryable ?? false;
  }
}

export function createSafeFetch(options = {}) {
  const policy = normalizePolicy(options);
  const cache = new Map();

  const safeFetch = async (input, init = {}) => {
    const target = await resolveSafeTarget(input, {
      ...policy,
      cache,
      signal: init?.signal,
    });
    return requestPinned(target, init, policy);
  };

  safeFetch.validateUrl = async (input, init = {}) =>
    resolveSafeTarget(input, {
      ...policy,
      cache,
      signal: init?.signal,
    });
  safeFetch.policy = Object.freeze({
    allowHttp: policy.allowHttp,
    allowPrivateNetworks: policy.allowPrivateNetworks,
    allowedHosts: [...policy.allowedHosts],
    allowedPorts: [...policy.allowedPorts],
    maxResponseBytes: policy.maxResponseBytes,
  });

  return safeFetch;
}

export async function resolveSafeTarget(input, options = {}) {
  const policy = normalizePolicy(options);
  const url = parseUpstreamUrl(input);

  if (url.protocol === "http:" && !policy.allowHttp) {
    throw new UpstreamSecurityError(
      "为避免 API Key 明文传输，上游地址默认只允许 HTTPS。",
      { code: "insecure_upstream_protocol" },
    );
  }

  const hostname = normalizeHostname(url.hostname);
  if (
    policy.allowedHosts.size > 0 &&
    !policy.allowedHosts.has(hostname)
  ) {
    throw new UpstreamSecurityError(
      "该上游域名不在服务端允许列表中。",
      { code: "upstream_host_not_allowed" },
    );
  }

  const port = Number(
    url.port || (url.protocol === "https:" ? 443 : 80),
  );
  if (!policy.allowedPorts.has(port)) {
    throw new UpstreamSecurityError(
      "该上游端口未被服务端允许。",
      { code: "upstream_port_not_allowed" },
    );
  }

  const addresses = await resolveAddresses(hostname, policy);
  if (addresses.length === 0) {
    throw new UpstreamSecurityError(
      "上游域名没有解析到可用地址。",
      {
        code: "upstream_dns_unavailable",
        retryable: true,
      },
    );
  }

  if (
    !policy.allowPrivateNetworks &&
    addresses.some(({ address }) => !isPublicAddress(address))
  ) {
    throw new UpstreamSecurityError(
      "上游地址解析到了内网、回环、链路本地或保留网络，已阻止请求。",
      { code: "private_upstream_blocked" },
    );
  }

  return {
    url,
    hostname,
    port,
    addresses,
    selectedAddress: addresses[0],
  };
}

export function isPublicAddress(value) {
  const address = stripIpv6Brackets(String(value ?? "").trim());
  const family = isIP(address);
  if (family === 4) {
    return !PROTECTED_NETWORKS.check(address, "ipv4");
  }
  if (family === 6) {
    return !PROTECTED_NETWORKS.check(address, "ipv6");
  }
  return false;
}

function normalizePolicy(options) {
  const allowHttp = options.allowHttp === true;
  const allowedPorts = new Set([
    443,
    ...(allowHttp ? [80] : []),
    ...normalizePorts(options.allowedPorts),
  ]);

  return {
    allowHttp,
    allowPrivateNetworks: options.allowPrivateNetworks === true,
    allowedHosts: normalizeHosts(options.allowedHosts),
    allowedPorts,
    resolver: options.resolver ?? dnsLookup,
    now: options.now ?? (() => Date.now()),
    dnsCacheMs: finiteInteger(
      options.dnsCacheMs,
      DEFAULT_DNS_CACHE_MS,
      0,
      5 * 60 * 1_000,
    ),
    dnsTimeoutMs: finiteInteger(
      options.dnsTimeoutMs,
      DEFAULT_DNS_TIMEOUT_MS,
      250,
      30_000,
    ),
    signal: options.signal,
    maxRequestBytes: finiteInteger(
      options.maxRequestBytes,
      DEFAULT_MAX_REQUEST_BYTES,
      1_024,
      1024 * 1_024,
    ),
    maxResponseBytes: finiteInteger(
      options.maxResponseBytes,
      DEFAULT_MAX_RESPONSE_BYTES,
      1_024,
      10 * 1024 * 1_024,
    ),
    maxResponseHeaderBytes: finiteInteger(
      options.maxResponseHeaderBytes,
      DEFAULT_MAX_RESPONSE_HEADER_BYTES,
      8 * 1_024,
      128 * 1_024,
    ),
    httpRequest: options.httpRequest ?? httpRequest,
    httpsRequest: options.httpsRequest ?? httpsRequest,
    cache: options.cache instanceof Map ? options.cache : new Map(),
  };
}

function parseUpstreamUrl(input) {
  const source = String(input ?? "").trim();
  if (!source || source.length > 2_048) {
    throw new UpstreamSecurityError("上游地址无效或长度超过限制。", {
      code: "invalid_upstream_url",
    });
  }

  let url;
  try {
    url = new URL(source);
  } catch {
    throw new UpstreamSecurityError("上游地址格式无效。", {
      code: "invalid_upstream_url",
    });
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new UpstreamSecurityError("上游地址仅支持 HTTP 或 HTTPS。", {
      code: "invalid_upstream_protocol",
    });
  }
  if (url.username || url.password) {
    throw new UpstreamSecurityError(
      "上游地址中不能包含用户名或密码。",
      { code: "upstream_credentials_not_allowed" },
    );
  }
  return url;
}

async function resolveAddresses(hostname, policy) {
  const literalFamily = isIP(hostname);
  if (literalFamily) {
    return [{ address: hostname, family: literalFamily }];
  }

  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  ) {
    return [{ address: "127.0.0.1", family: 4 }];
  }

  const now = policy.now();
  const cached = policy.cache.get(hostname);
  if (cached?.expiresAt > now) {
    return cached.addresses.map((entry) => ({ ...entry }));
  }

  let result;
  try {
    result = await withDeadline(
      policy.resolver(hostname, {
        all: true,
        verbatim: true,
      }),
      policy,
    );
  } catch (error) {
    if (
      error instanceof UpstreamSecurityError ||
      ["AbortError", "TimeoutError"].includes(error?.name)
    ) {
      throw error;
    }
    throw new UpstreamSecurityError(
      "无法解析上游域名。",
      {
        code: "upstream_dns_failed",
        retryable: true,
        cause: error,
      },
    );
  }

  const entries = (Array.isArray(result) ? result : [result])
    .map((entry) => ({
      address: stripIpv6Brackets(
        String(entry?.address ?? "").trim(),
      ),
      family: Number(entry?.family) || isIP(entry?.address),
    }))
    .filter(
      ({ address, family }) =>
        Boolean(address) &&
        ((family === 4 && isIP(address) === 4) ||
          (family === 6 && isIP(address) === 6)),
    );

  const unique = [
    ...new Map(
      entries.map((entry) => [
        `${entry.family}:${entry.address}`,
        entry,
      ]),
    ).values(),
  ];
  policy.cache.set(hostname, {
    addresses: unique,
    expiresAt: now + policy.dnsCacheMs,
  });
  return unique;
}

function withDeadline(promise, policy) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      policy.signal?.removeEventListener("abort", abort);
      callback(value);
    };
    const abort = () => {
      finish(
        reject,
        policy.signal?.reason instanceof Error
          ? policy.signal.reason
          : new DOMException("The request was aborted.", "AbortError"),
      );
    };
    const timeout = setTimeout(() => {
      finish(
        reject,
        new UpstreamSecurityError("上游域名解析超时。", {
          code: "upstream_dns_timeout",
          retryable: true,
        }),
      );
    }, policy.dnsTimeoutMs);

    if (policy.signal?.aborted) {
      abort();
      return;
    }
    policy.signal?.addEventListener("abort", abort, {
      once: true,
    });
    Promise.resolve(promise).then(
      (value) => finish(resolve, value),
      (error) => finish(reject, error),
    );
  });
}

function requestPinned(target, init, policy) {
  const method = String(init?.method ?? "GET").toUpperCase();
  if (!["GET", "POST"].includes(method)) {
    throw new UpstreamSecurityError(
      "安全请求器只允许 GET 或 POST。",
      { code: "upstream_method_not_allowed" },
    );
  }
  if (init?.redirect && init.redirect !== "manual") {
    throw new UpstreamSecurityError(
      "安全请求器禁止自动跟随重定向。",
      { code: "unsafe_redirect_mode" },
    );
  }

  const body = normalizeRequestBody(init?.body);
  if (body.length > policy.maxRequestBytes) {
    throw new UpstreamSecurityError("上游请求内容超过安全限制。", {
      code: "upstream_request_too_large",
    });
  }

  const headers = new Headers(init?.headers);
  for (const name of [
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "transfer-encoding",
  ]) {
    headers.delete(name);
  }
  if (body.length > 0) {
    headers.set("Content-Length", String(body.length));
  }

  const requestHeaders = Object.fromEntries(headers.entries());
  const transport =
    target.url.protocol === "https:"
      ? policy.httpsRequest
      : policy.httpRequest;

  return new Promise((resolve, reject) => {
    let settled = false;
    let request;
    const signal = init?.signal;

    const finishReject = (error) => {
      if (settled) return;
      settled = true;
      removeAbortListener();
      reject(error);
    };
    const finishResolve = (value) => {
      if (settled) return;
      settled = true;
      removeAbortListener();
      resolve(value);
    };
    const abortRequest = () => {
      const reason =
        signal?.reason instanceof Error
          ? signal.reason
          : new DOMException("The request was aborted.", "AbortError");
      request?.destroy(reason);
      finishReject(reason);
    };
    const removeAbortListener = () => {
      signal?.removeEventListener("abort", abortRequest);
    };

    if (signal?.aborted) {
      abortRequest();
      return;
    }

    const pinned = target.selectedAddress;
    const pinnedLookup = (_hostname, lookupOptions, callback) => {
      if (lookupOptions?.all) {
        callback(null, [{ ...pinned }]);
        return;
      }
      callback(null, pinned.address, pinned.family);
    };

    try {
      request = transport(target.url, {
        method,
        headers: requestHeaders,
        lookup: pinnedLookup,
        agent: false,
        maxHeaderSize: policy.maxResponseHeaderBytes,
        rejectUnauthorized: true,
      });
    } catch (error) {
      finishReject(error);
      return;
    }

    signal?.addEventListener("abort", abortRequest, { once: true });
    request.once("error", finishReject);
    request.once("response", (incoming) => {
      const chunks = [];
      let size = 0;

      incoming.on("data", (chunk) => {
        if (settled) return;
        const buffer = Buffer.isBuffer(chunk)
          ? chunk
          : Buffer.from(chunk);
        size += buffer.length;
        if (size > policy.maxResponseBytes) {
          const error = new UpstreamSecurityError(
            "上游响应内容超过安全限制。",
            { code: "upstream_response_too_large" },
          );
          incoming.destroy(error);
          request.destroy(error);
          finishReject(error);
          return;
        }
        chunks.push(buffer);
      });
      incoming.once("error", finishReject);
      incoming.once("end", () => {
        const status = incoming.statusCode ?? 502;
        const bodyBuffer = Buffer.concat(chunks);
        const responseHeaders = new Headers();
        for (
          let index = 0;
          index < incoming.rawHeaders.length;
          index += 2
        ) {
          responseHeaders.append(
            incoming.rawHeaders[index],
            incoming.rawHeaders[index + 1],
          );
        }
        const bodyAllowed = ![204, 205, 304].includes(status);
        finishResolve(
          new Response(bodyAllowed ? bodyBuffer : null, {
            status,
            headers: responseHeaders,
          }),
        );
      });
    });

    if (body.length > 0) request.write(body);
    request.end();
  });
}

function normalizeRequestBody(value) {
  if (value === undefined || value === null) return Buffer.alloc(0);
  if (typeof value === "string") return Buffer.from(value);
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new UpstreamSecurityError(
    "安全请求器不支持该请求内容类型。",
    { code: "unsupported_upstream_body" },
  );
}

function normalizeHosts(values) {
  const list =
    values instanceof Set
      ? [...values]
      : Array.isArray(values)
        ? values
        : String(values ?? "").split(",");
  return new Set(
    list
      .map((value) => normalizeHostname(value))
      .filter(Boolean),
  );
}

function normalizeHostname(value) {
  return stripIpv6Brackets(
    String(value ?? "").trim().toLowerCase().replace(/\.$/, ""),
  );
}

function normalizePorts(values) {
  const list =
    values instanceof Set
      ? [...values]
      : Array.isArray(values)
        ? values
        : String(values ?? "").split(",");
  return list
    .map(Number)
    .filter(
      (port) =>
        Number.isInteger(port) && port >= 1 && port <= 65_535,
    );
}

function stripIpv6Brackets(value) {
  return value.startsWith("[") && value.endsWith("]")
    ? value.slice(1, -1)
    : value;
}

function finiteInteger(value, fallback, min, max) {
  const number = Number(value);
  return Number.isInteger(number) && number >= min && number <= max
    ? number
    : fallback;
}

function createProtectedNetworkList() {
  const blockList = new BlockList();
  for (const [network, prefix] of [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.88.99.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ]) {
    blockList.addSubnet(network, prefix, "ipv4");
  }
  for (const [network, prefix] of [
    ["::", 96],
    ["::1", 128],
    ["64:ff9b::", 96],
    ["64:ff9b:1::", 48],
    ["100::", 64],
    ["2001::", 23],
    ["2001:db8::", 32],
    ["2002::", 16],
    ["fc00::", 7],
    ["fe80::", 10],
    ["ff00::", 8],
  ]) {
    blockList.addSubnet(network, prefix, "ipv6");
  }
  return blockList;
}
