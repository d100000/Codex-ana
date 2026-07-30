import { randomBytes, randomInt } from "node:crypto";

export const DEFAULT_PROTECTION_CONFIG = Object.freeze({
  cooldownMs: 5 * 60 * 1_000,
  challengeTtlMs: 2 * 60 * 1_000,
  proofTtlMs: 90 * 1_000,
  challengeWindowMs: 5 * 60 * 1_000,
  maxChallengesPerWindow: 12,
  modelLookupWindowMs: 5 * 60 * 1_000,
  maxModelLookupsPerWindow: 6,
  minDragDurationMs: 450,
  maxDragDurationMs: 15_000,
  minTraceSamples: 8,
  targetTolerance: 40,
  maxStateEntries: 20_000,
});

export class AbuseProtectionError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = "AbuseProtectionError";
    this.code = options.code ?? "abuse_protection_error";
    this.httpStatus = options.httpStatus ?? 400;
    this.retryAfterSeconds = options.retryAfterSeconds ?? null;
  }
}

export class AbuseProtection {
  constructor(options = {}) {
    this.config = {
      ...DEFAULT_PROTECTION_CONFIG,
      ...(options.config ?? {}),
    };
    this.now = options.now ?? (() => Date.now());
    this.randomInt = options.randomInt ?? randomInt;
    this.tokenFactory =
      options.tokenFactory ??
      (() => randomBytes(24).toString("base64url"));

    this.challenges = new Map();
    this.activeChallenges = new Map();
    this.proofs = new Map();
    this.cooldowns = {
      ip: new Map(),
      device: new Map(),
    };
    this.challengeWindows = {
      ip: new Map(),
      device: new Map(),
    };
    this.modelLookupWindows = {
      ip: new Map(),
      device: new Map(),
    };
    this.lastCleanupAt = 0;
  }

  issueChallenge({ ipKey, deviceKey }) {
    const now = this.now();
    this.cleanup(now);
    validateIdentityKeys(ipKey, deviceKey);
    this.assertCooldownAvailable(ipKey, deviceKey, now);

    const ipWindow = this.currentWindow(
      this.challengeWindows.ip,
      ipKey,
      now,
    );
    const deviceWindow = this.currentWindow(
      this.challengeWindows.device,
      deviceKey,
      now,
    );
    this.assertChallengeWindow(ipWindow, now);
    this.assertChallengeWindow(deviceWindow, now);
    this.ensureCapacity();

    const previousId = this.activeChallenges.get(deviceKey);
    if (previousId) this.challenges.delete(previousId);

    const target = roundToStep(this.randomInt(620, 881), 5);
    const id = this.tokenFactory();
    const challenge = {
      id,
      ipKey,
      deviceKey,
      target,
      createdAt: now,
      expiresAt: now + this.config.challengeTtlMs,
    };
    this.challenges.set(id, challenge);
    this.activeChallenges.set(deviceKey, id);
    this.recordWindow(this.challengeWindows.ip, ipKey, ipWindow, now);
    this.recordWindow(
      this.challengeWindows.device,
      deviceKey,
      deviceWindow,
      now,
    );

    return {
      id,
      target,
      tolerance: this.config.targetTolerance,
      minDurationMs: this.config.minDragDurationMs,
      expiresInSeconds: Math.ceil(this.config.challengeTtlMs / 1_000),
    };
  }

  verifyChallenge({
    challengeId,
    ipKey,
    deviceKey,
    finalPosition,
    trace,
  }) {
    const now = this.now();
    this.cleanup(now);
    validateIdentityKeys(ipKey, deviceKey);

    const id = String(challengeId ?? "");
    const challenge = this.challenges.get(id);
    if (!challenge) {
      throw verificationError(
        "滑块验证不存在或已经使用，请重新验证。",
        "verification_expired",
      );
    }

    this.challenges.delete(id);
    if (this.activeChallenges.get(challenge.deviceKey) === id) {
      this.activeChallenges.delete(challenge.deviceKey);
    }

    if (
      challenge.expiresAt <= now ||
      challenge.ipKey !== ipKey ||
      challenge.deviceKey !== deviceKey
    ) {
      throw verificationError(
        "滑块验证已过期，请重新验证。",
        "verification_expired",
      );
    }

    if (
      now - challenge.createdAt <
      this.config.minDragDurationMs
    ) {
      throw verificationError(
        "滑块拖动过快，请自然拖动后重试。",
        "verification_failed",
      );
    }

    validateSliderTrace({
      finalPosition,
      trace,
      target: challenge.target,
      config: this.config,
    });
    this.ensureCapacity();

    const proof = this.tokenFactory();
    this.proofs.set(proof, {
      ipKey,
      deviceKey,
      createdAt: now,
      expiresAt: now + this.config.proofTtlMs,
    });

    return {
      proof,
      expiresInSeconds: Math.ceil(this.config.proofTtlMs / 1_000),
    };
  }

  consumeProofAndReserve({ proof, ipKey, deviceKey }) {
    const now = this.now();
    this.cleanup(now);
    validateIdentityKeys(ipKey, deviceKey);

    const token = String(proof ?? "");
    const verified = this.proofs.get(token);
    if (
      !verified ||
      verified.expiresAt <= now ||
      verified.ipKey !== ipKey ||
      verified.deviceKey !== deviceKey
    ) {
      if (verified) this.proofs.delete(token);
      throw verificationError(
        "请先完成当前设备上的滑块验证。",
        "verification_required",
      );
    }

    this.assertCooldownAvailable(ipKey, deviceKey, now);
    this.proofs.delete(token);

    const nextAllowedAt = now + this.config.cooldownMs;
    this.cooldowns.ip.set(ipKey, nextAllowedAt);
    this.cooldowns.device.set(deviceKey, nextAllowedAt);

    return {
      nextAllowedAt,
      cooldownSeconds: Math.ceil(this.config.cooldownMs / 1_000),
    };
  }

  remainingCooldown({ ipKey, deviceKey }) {
    const now = this.now();
    this.cleanup(now);
    validateIdentityKeys(ipKey, deviceKey);
    return Math.max(
      0,
      (this.cooldowns.ip.get(ipKey) ?? 0) - now,
      (this.cooldowns.device.get(deviceKey) ?? 0) - now,
    );
  }

  reserveModelLookup({ ipKey, deviceKey }) {
    const now = this.now();
    this.cleanup(now);
    validateIdentityKeys(ipKey, deviceKey);

    const ipWindow = this.currentWindow(
      this.modelLookupWindows.ip,
      ipKey,
      now,
      this.config.modelLookupWindowMs,
    );
    const deviceWindow = this.currentWindow(
      this.modelLookupWindows.device,
      deviceKey,
      now,
      this.config.modelLookupWindowMs,
    );
    this.assertRollingWindowAvailable(
      ipWindow,
      now,
      this.config.modelLookupWindowMs,
      this.config.maxModelLookupsPerWindow,
    );
    this.assertRollingWindowAvailable(
      deviceWindow,
      now,
      this.config.modelLookupWindowMs,
      this.config.maxModelLookupsPerWindow,
    );
    this.ensureCapacity();
    this.recordWindow(this.modelLookupWindows.ip, ipKey, ipWindow, now);
    this.recordWindow(
      this.modelLookupWindows.device,
      deviceKey,
      deviceWindow,
      now,
    );

    return {
      remaining: Math.min(
        this.config.maxModelLookupsPerWindow - ipWindow.length - 1,
        this.config.maxModelLookupsPerWindow -
          deviceWindow.length -
          1,
      ),
    };
  }

  assertCooldownAvailable(ipKey, deviceKey, now) {
    const remainingMs = Math.max(
      0,
      (this.cooldowns.ip.get(ipKey) ?? 0) - now,
      (this.cooldowns.device.get(deviceKey) ?? 0) - now,
    );
    if (remainingMs <= 0) return;

    throw new AbuseProtectionError(
      "请求过于频繁，每个 IP 或设备 5 分钟只能启动一次分析。",
      {
        code: "rate_limited",
        httpStatus: 429,
        retryAfterSeconds: coarseRetryAfter(remainingMs),
      },
    );
  }

  assertChallengeWindow(window, now) {
    if (window.length < this.config.maxChallengesPerWindow) return;
    const remainingMs =
      window[0] + this.config.challengeWindowMs - now;
    throw new AbuseProtectionError(
      "验证请求过于频繁，请稍后再试。",
      {
        code: "challenge_rate_limited",
        httpStatus: 429,
        retryAfterSeconds: coarseRetryAfter(remainingMs),
      },
    );
  }

  assertRollingWindowAvailable(
    window,
    now,
    windowMs,
    maximum,
  ) {
    if (window.length < maximum) return;
    const remainingMs = window[0] + windowMs - now;
    throw new AbuseProtectionError(
      "模型列表读取过于频繁，请稍后再试。",
      {
        code: "model_lookup_rate_limited",
        httpStatus: 429,
        retryAfterSeconds: coarseRetryAfter(remainingMs),
      },
    );
  }

  currentWindow(
    map,
    key,
    now,
    windowMs = this.config.challengeWindowMs,
  ) {
    const cutoff = now - windowMs;
    return (map.get(key) ?? []).filter((timestamp) => timestamp > cutoff);
  }

  recordWindow(map, key, window, now) {
    map.set(key, [...window, now]);
  }

  ensureCapacity() {
    const entryCount =
      this.challenges.size +
      this.proofs.size +
      this.cooldowns.ip.size +
      this.cooldowns.device.size +
      this.challengeWindows.ip.size +
      this.challengeWindows.device.size +
      this.modelLookupWindows.ip.size +
      this.modelLookupWindows.device.size;
    if (entryCount < this.config.maxStateEntries) return;

    throw new AbuseProtectionError(
      "验证服务当前繁忙，请稍后再试。",
      {
        code: "protection_capacity_reached",
        httpStatus: 503,
      },
    );
  }

  cleanup(now = this.now()) {
    if (now - this.lastCleanupAt < 30_000) return;
    this.lastCleanupAt = now;

    for (const [id, challenge] of this.challenges) {
      if (challenge.expiresAt > now) continue;
      this.challenges.delete(id);
      if (this.activeChallenges.get(challenge.deviceKey) === id) {
        this.activeChallenges.delete(challenge.deviceKey);
      }
    }
    for (const [token, proof] of this.proofs) {
      if (proof.expiresAt <= now) this.proofs.delete(token);
    }
    for (const map of Object.values(this.cooldowns)) {
      for (const [key, expiresAt] of map) {
        if (expiresAt <= now) map.delete(key);
      }
    }
    for (const map of Object.values(this.challengeWindows)) {
      const cutoff = now - this.config.challengeWindowMs;
      for (const [key, timestamps] of map) {
        const current = timestamps.filter(
          (timestamp) => timestamp > cutoff,
        );
        if (current.length > 0) map.set(key, current);
        else map.delete(key);
      }
    }
    for (const map of Object.values(this.modelLookupWindows)) {
      const cutoff = now - this.config.modelLookupWindowMs;
      for (const [key, timestamps] of map) {
        const current = timestamps.filter(
          (timestamp) => timestamp > cutoff,
        );
        if (current.length > 0) map.set(key, current);
        else map.delete(key);
      }
    }
  }
}

function validateSliderTrace({
  finalPosition,
  trace,
  target,
  config,
}) {
  const final = Number(finalPosition);
  if (
    !Number.isFinite(final) ||
    Math.abs(final - target) > config.targetTolerance
  ) {
    throw verificationError(
      "滑块没有与缺口对齐，请重试。",
      "verification_failed",
    );
  }

  if (
    !Array.isArray(trace) ||
    trace.length < config.minTraceSamples ||
    trace.length > 180
  ) {
    throw verificationError(
      "滑块轨迹不足，请从左侧自然拖动到缺口。",
      "verification_failed",
    );
  }

  const points = trace.map((point) => {
    const position = Number(Array.isArray(point) ? point[0] : point?.position);
    const elapsed = Number(Array.isArray(point) ? point[1] : point?.elapsed);
    if (
      !Number.isFinite(position) ||
      !Number.isFinite(elapsed) ||
      position < 0 ||
      position > 1_000 ||
      elapsed < 0 ||
      elapsed > config.maxDragDurationMs + 1_000
    ) {
      throw verificationError(
        "滑块轨迹无效，请重新验证。",
        "verification_failed",
      );
    }
    return { position, elapsed };
  });

  for (let index = 1; index < points.length; index += 1) {
    if (points[index].elapsed < points[index - 1].elapsed) {
      throw verificationError(
        "滑块轨迹无效，请重新验证。",
        "verification_failed",
      );
    }
  }

  const duration =
    points.at(-1).elapsed - points[0].elapsed;
  const positions = points.map(({ position }) => position);
  const movement = Math.max(...positions) - Math.min(...positions);
  const uniquePositions = new Set(
    positions.map((position) => Math.round(position / 5)),
  ).size;

  if (
    duration < config.minDragDurationMs ||
    duration > config.maxDragDurationMs ||
    points[0].position > 80 ||
    movement < target * 0.65 ||
    uniquePositions < 6 ||
    Math.abs(points.at(-1).position - final) > 30
  ) {
    throw verificationError(
      "滑块轨迹未通过验证，请自然拖动后重试。",
      "verification_failed",
    );
  }
}

function verificationError(message, code) {
  return new AbuseProtectionError(message, {
    code,
    httpStatus: 403,
  });
}

function validateIdentityKeys(ipKey, deviceKey) {
  if (
    typeof ipKey !== "string" ||
    !ipKey ||
    typeof deviceKey !== "string" ||
    !deviceKey
  ) {
    throw new AbuseProtectionError("无法识别当前请求来源。", {
      code: "identity_unavailable",
      httpStatus: 400,
    });
  }
}

function roundToStep(value, step) {
  return Math.round(value / step) * step;
}

function coarseRetryAfter(remainingMs) {
  const seconds = Math.max(1, Math.ceil(remainingMs / 1_000));
  return Math.ceil(seconds / 15) * 15;
}
