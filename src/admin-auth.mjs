import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

export const DEFAULT_ADMIN_AUTH_CONFIG = Object.freeze({
  sessionTtlMs: 8 * 60 * 60 * 1_000,
  loginWindowMs: 15 * 60 * 1_000,
  maxLoginFailures: 5,
  maxStateEntries: 10_000,
});

export class AdminAuthError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = "AdminAuthError";
    this.code = options.code ?? "admin_auth_error";
    this.httpStatus = options.httpStatus ?? 401;
    this.retryAfterSeconds = options.retryAfterSeconds ?? null;
  }
}

export class AdminAuth {
  constructor(options = {}) {
    this.config = {
      ...DEFAULT_ADMIN_AUTH_CONFIG,
      ...(options.config ?? {}),
    };
    this.now = options.now ?? (() => Date.now());
    this.tokenFactory =
      options.tokenFactory ??
      (() => randomBytes(24).toString("base64url"));
    this.secret = normalizeSecret(options.secret);
    this.passwordDigest = options.password
      ? digest(String(options.password))
      : null;
    this.loginFailures = {
      ip: new Map(),
      device: new Map(),
    };
  }

  get enabled() {
    return this.passwordDigest !== null;
  }

  createSession({ password, ipKey, deviceKey }) {
    this.assertEnabled();
    validateIdentity(ipKey, deviceKey);
    const now = this.now();
    this.cleanup(now);
    this.assertLoginAvailable(ipKey, deviceKey, now);

    const candidateDigest = digest(String(password ?? ""));
    if (!timingSafeEqual(candidateDigest, this.passwordDigest)) {
      this.recordFailure(ipKey, deviceKey, now);
      this.assertLoginAvailable(ipKey, deviceKey, now);
      throw new AdminAuthError("管理密码不正确。", {
        code: "invalid_admin_credentials",
        httpStatus: 401,
      });
    }

    this.loginFailures.ip.delete(ipKey);
    this.loginFailures.device.delete(deviceKey);

    const expiresAt = now + this.config.sessionTtlMs;
    const payload = [
      "v1",
      expiresAt,
      this.tokenFactory(),
      deviceKey,
    ].join(".");
    const signature = this.sign(payload);
    return {
      token: `${payload}.${signature}`,
      expiresAt,
      expiresInSeconds: Math.ceil(this.config.sessionTtlMs / 1_000),
    };
  }

  verifySession(token, deviceKey) {
    if (!this.enabled) return false;
    validateIdentity("session", deviceKey);

    const source = String(token ?? "");
    if (!source || source.length > 1_024) return false;
    const parts = source.split(".");
    if (parts.length !== 5 || parts[0] !== "v1") return false;

    const [version, expiresSource, nonce, boundDevice, signature] =
      parts;
    const expiresAt = Number(expiresSource);
    if (
      version !== "v1" ||
      !Number.isSafeInteger(expiresAt) ||
      expiresAt <= this.now() ||
      expiresAt > this.now() + this.config.sessionTtlMs ||
      !/^[A-Za-z0-9_-]{16,128}$/.test(nonce) ||
      boundDevice !== deviceKey ||
      !/^[A-Za-z0-9_-]{32,128}$/.test(signature)
    ) {
      return false;
    }

    const payload = parts.slice(0, 4).join(".");
    return safeStringEqual(signature, this.sign(payload));
  }

  assertEnabled() {
    if (this.enabled) return;
    throw new AdminAuthError(
      "管理后台尚未配置访问密码。",
      {
        code: "admin_disabled",
        httpStatus: 503,
      },
    );
  }

  assertLoginAvailable(ipKey, deviceKey, now) {
    for (const [map, key] of [
      [this.loginFailures.ip, ipKey],
      [this.loginFailures.device, deviceKey],
    ]) {
      const failures = this.currentFailures(map, key, now);
      if (failures.length < this.config.maxLoginFailures) continue;
      const retryAfterMs =
        failures[0] + this.config.loginWindowMs - now;
      throw new AdminAuthError(
        "管理后台登录尝试过多，请稍后再试。",
        {
          code: "admin_login_rate_limited",
          httpStatus: 429,
          retryAfterSeconds: Math.max(
            1,
            Math.ceil(retryAfterMs / 1_000),
          ),
        },
      );
    }
  }

  recordFailure(ipKey, deviceKey, now) {
    this.ensureCapacity();
    for (const [map, key] of [
      [this.loginFailures.ip, ipKey],
      [this.loginFailures.device, deviceKey],
    ]) {
      const failures = this.currentFailures(map, key, now);
      failures.push(now);
      map.set(key, failures);
    }
  }

  currentFailures(map, key, now) {
    return (map.get(key) ?? []).filter(
      (timestamp) =>
        timestamp > now - this.config.loginWindowMs,
    );
  }

  cleanup(now) {
    for (const map of Object.values(this.loginFailures)) {
      for (const [key, timestamps] of map) {
        const current = timestamps.filter(
          (timestamp) =>
            timestamp > now - this.config.loginWindowMs,
        );
        if (current.length === 0) map.delete(key);
        else map.set(key, current);
      }
    }
  }

  ensureCapacity() {
    for (const map of Object.values(this.loginFailures)) {
      while (map.size >= this.config.maxStateEntries) {
        map.delete(map.keys().next().value);
      }
    }
  }

  sign(payload) {
    return createHmac("sha256", this.secret)
      .update(payload)
      .digest("base64url");
  }
}

function normalizeSecret(value) {
  if (Buffer.isBuffer(value) && value.length >= 32) {
    return Buffer.from(value);
  }
  const source = String(value ?? "");
  if (Buffer.byteLength(source) >= 32) {
    return Buffer.from(source);
  }
  throw new TypeError(
    "管理员会话签名密钥必须至少包含 32 字节。",
  );
}

function digest(value) {
  return createHash("sha256").update(value).digest();
}

function safeStringEqual(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));
  return (
    leftBuffer.length === rightBuffer.length &&
    timingSafeEqual(leftBuffer, rightBuffer)
  );
}

function validateIdentity(ipKey, deviceKey) {
  if (
    !String(ipKey ?? "").trim() ||
    !String(deviceKey ?? "").trim()
  ) {
    throw new AdminAuthError("管理员身份信息无效。", {
      code: "invalid_admin_identity",
      httpStatus: 400,
    });
  }
}
