import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT_DIR = fileURLToPath(new URL("..", import.meta.url));
const PORT = Number(process.env.INTEGRATION_PORT || 4397);
const ADMIN_PASSWORD = "integration-admin-password";
const TEST_DATA_DIR = await mkdtemp(
  join(tmpdir(), "planscope-security-"),
);
const child = spawn(process.execPath, ["server.mjs"], {
  cwd: ROOT_DIR,
  env: {
    ...process.env,
    HOST: "127.0.0.1",
    PORT: String(PORT),
    ALLOW_HTTP_UPSTREAMS: "",
    ALLOW_PRIVATE_UPSTREAMS: "",
    ADMIN_PASSWORD,
    ADMIN_SESSION_SECRET: "s".repeat(32),
    PLANSCOPE_DATA_DIR: join(TEST_DATA_DIR, "primary"),
  },
  stdio: ["ignore", "pipe", "pipe"],
});

try {
  await waitForReady(child);

  const health = await send();
  assert.equal(health.status, 200);
  assert.equal(health.headers["x-frame-options"], "DENY");
  assert.equal(
    health.headers["cross-origin-resource-policy"],
    "same-origin",
  );
  assert.match(
    health.headers["content-security-policy"],
    /object-src 'none'/,
  );
  assert.equal(health.json.protection.adminHistory.enabled, true);
  assert.equal(
    health.json.protection.requestLog.retentionSeconds,
    86_400,
  );

  const rebinding = await send({
    headers: { Host: `attacker.example:${PORT}` },
  });
  assert.equal(rebinding.status, 421);
  assert.equal(rebinding.json.error.code, "misdirected_request");

  const missingIntent = await send({
    method: "POST",
    path: "/api/verification/challenge",
  });
  assert.equal(missingIntent.status, 403);
  assert.equal(
    missingIntent.json.error.code,
    "api_intent_required",
  );

  const crossSite = await send({
    method: "POST",
    path: "/api/verification/challenge",
    headers: {
      "X-PlanScope-Request": "1",
      "Sec-Fetch-Site": "cross-site",
    },
  });
  assert.equal(crossSite.status, 403);
  assert.equal(
    crossSite.json.error.code,
    "cross_site_request_blocked",
  );

  const wrongContentType = await send({
    method: "POST",
    path: "/api/models",
    headers: {
      "X-PlanScope-Request": "1",
      "Content-Type": "text/plain",
    },
    body: "{}",
  });
  assert.equal(wrongContentType.status, 415);

  const challenge = await send({
    method: "POST",
    path: "/api/verification/challenge",
    headers: { "X-PlanScope-Request": "1" },
  });
  assert.equal(challenge.status, 201);
  assert.match(
    challenge.headers["set-cookie"][0],
    /HttpOnly; SameSite=Strict/,
  );

  const privateTarget = await send({
    method: "POST",
    path: "/api/models",
    headers: {
      "X-PlanScope-Request": "1",
      "Content-Type": "application/json",
      Cookie: cookiePair(challenge.headers["set-cookie"][0]),
    },
    body: JSON.stringify({
      baseUrl: "https://169.254.169.254",
      apiKey: "sk-integration-test",
    }),
  });
  assert.equal(privateTarget.status, 400);
  assert.equal(
    privateTarget.json.error.code,
    "private_upstream_blocked",
  );

  const adminSession = await send({
    path: "/api/admin/session",
  });
  assert.equal(adminSession.status, 200);
  assert.equal(adminSession.json.enabled, true);
  assert.equal(adminSession.json.authenticated, false);
  const adminDeviceCookie = cookieByName(
    adminSession.headers["set-cookie"],
    "planscope_device",
  );

  const unauthenticatedHistory = await send({
    path: "/api/admin/history",
    headers: { Cookie: adminDeviceCookie },
  });
  assert.equal(unauthenticatedHistory.status, 401);
  assert.equal(
    unauthenticatedHistory.json.error.code,
    "admin_authentication_required",
  );
  const unauthenticatedRequestLogs = await send({
    path: "/api/admin/request-logs",
    headers: { Cookie: adminDeviceCookie },
  });
  assert.equal(unauthenticatedRequestLogs.status, 401);

  const adminLogin = await send({
    method: "POST",
    path: "/api/admin/login",
    headers: jsonHeaders(adminDeviceCookie),
    body: JSON.stringify({ password: ADMIN_PASSWORD }),
  });
  assert.equal(adminLogin.status, 200);
  const adminCookie = cookieByName(
    adminLogin.headers["set-cookie"],
    "planscope_admin",
  );
  const authenticatedCookies =
    `${adminDeviceCookie}; ${adminCookie}`;

  const emptyHistory = await send({
    path: "/api/admin/history",
    headers: { Cookie: authenticatedCookies },
  });
  assert.equal(emptyHistory.status, 200);
  assert.deepEqual(emptyHistory.json.records, []);

  const logSecret = "sk-request-log-integration-secret";
  const loggedHealth = await send({
    path: `/api/health?api_key=${logSecret}`,
    headers: { Cookie: authenticatedCookies },
  });
  assert.equal(loggedHealth.status, 200);
  const requestLogs = await send({
    path: "/api/admin/request-logs?q=%2Fapi%2Fhealth",
    headers: { Cookie: authenticatedCookies },
  });
  assert.equal(requestLogs.status, 200);
  assert.ok(requestLogs.json.records.length >= 1);
  assert.ok(
    requestLogs.json.records.every(
      (record) => record.path === "/api/health",
    ),
  );
  assert.doesNotMatch(requestLogs.text, new RegExp(logSecret));
  assert.doesNotMatch(
    requestLogs.text,
    /authorization|cookie|apiKey|query/i,
  );

  const foreignAdminDevice = await send({
    path: "/api/admin/history",
    headers: { Cookie: adminCookie },
  });
  assert.equal(foreignAdminDevice.status, 401);

  console.log(
    JSON.stringify({
      health: health.status,
      dnsRebindingHost: rebinding.status,
      missingIntent: missingIntent.status,
      crossSite: crossSite.status,
      contentType: wrongContentType.status,
      challenge: challenge.status,
      privateTarget: privateTarget.status,
      privateTargetCode: privateTarget.json.error.code,
      adminLogin: adminLogin.status,
      adminHistory: emptyHistory.status,
      requestLogs: requestLogs.status,
      foreignAdminDevice: foreignAdminDevice.status,
    }),
  );
} finally {
  child.kill("SIGTERM");
  await waitForExit(child);
}

try {
  await verifyJobOwnership();
} finally {
  await rm(TEST_DATA_DIR, { recursive: true, force: true });
}

function send(options = {}) {
  const body = String(options.body ?? "");
  const port = Number(options.port ?? PORT);
  return new Promise((resolve, reject) => {
    const outgoing = request(
      {
        host: "127.0.0.1",
        port,
        path: options.path ?? "/api/health",
        method: options.method ?? "GET",
        headers: {
          Host: `127.0.0.1:${port}`,
          ...(body
            ? { "Content-Length": Buffer.byteLength(body) }
            : {}),
          ...(options.headers ?? {}),
        },
      },
      (incoming) => {
        const chunks = [];
        incoming.on("data", (chunk) => chunks.push(chunk));
        incoming.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          resolve({
            status: incoming.statusCode,
            headers: incoming.headers,
            text,
            json: parseJson(text),
          });
        });
      },
    );
    outgoing.once("error", reject);
    if (body) outgoing.write(body);
    outgoing.end();
  });
}

async function verifyJobOwnership() {
  const mockPort = PORT + 1;
  const appPort = PORT + 2;
  const mock = spawn(process.execPath, ["test/mock-upstream.mjs"], {
    cwd: ROOT_DIR,
    env: {
      ...process.env,
      MOCK_PORT: String(mockPort),
      MOCK_FAIL_FIRST_SAMPLE_ONCE: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const app = spawn(process.execPath, ["server.mjs"], {
    cwd: ROOT_DIR,
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: String(appPort),
      ALLOW_HTTP_UPSTREAMS: "1",
      ALLOW_PRIVATE_UPSTREAMS: "1",
      ALLOWED_UPSTREAM_PORTS: String(mockPort),
      ADMIN_PASSWORD,
      ADMIN_SESSION_SECRET: "s".repeat(32),
      PLANSCOPE_DATA_DIR: join(TEST_DATA_DIR, "ownership"),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await Promise.all([
      waitForOutput(mock, "PlanScope 模拟上游"),
      waitForOutput(app, "Codex PlanScope 已启动"),
    ]);

    const challenge = await send({
      port: appPort,
      method: "POST",
      path: "/api/verification/challenge",
      headers: { "X-PlanScope-Request": "1" },
    });
    assert.equal(challenge.status, 201);
    const ownerCookie = cookiePair(
      challenge.headers["set-cookie"][0],
    );
    await new Promise((resolve) => setTimeout(resolve, 550));

    const target = Number(challenge.json.target);
    const verification = await send({
      port: appPort,
      method: "POST",
      path: "/api/verification/verify",
      headers: jsonHeaders(ownerCookie),
      body: JSON.stringify({
        challengeId: challenge.json.id,
        finalPosition: target,
        trace: Array.from({ length: 11 }, (_, index) => [
          Math.round((target * index) / 10),
          index * 90,
        ]),
      }),
    });
    assert.equal(verification.status, 200);

    const analysis = await send({
      port: appPort,
      method: "POST",
      path: "/api/analyze",
      headers: jsonHeaders(ownerCookie),
      body: JSON.stringify({
        baseUrl: `http://localhost:${mockPort}`,
        apiKey: "sk-test-local",
        model: "gpt-5.5",
        verificationProof: verification.json.proof,
      }),
    });
    assert.equal(analysis.status, 202);

    const terminalEventsPromise = send({
      port: appPort,
      path: analysis.json.events,
      headers: { Cookie: ownerCookie },
    });

    const ownerRead = await waitForFirstSample(
      appPort,
      analysis.json.location,
      ownerCookie,
    );
    assert.equal(ownerRead.status, 200);
    assert.equal(ownerRead.json.samples[0].status, "classified");
    assert.equal(ownerRead.json.samples[0].plan.key, "pro");
    assert.equal(
      ownerRead.json.samples[0].failureDetails.length,
      1,
    );
    assert.equal(
      ownerRead.json.samples[0].failureDetails[0].response.status,
      503,
    );
    assert.match(
      ownerRead.json.samples[0].failureDetails[0].response.body,
      /\[REDACTED\]/,
    );
    assert.doesNotMatch(ownerRead.text, /sk-test-local/);

    const foreignRead = await send({
      port: appPort,
      path: analysis.json.location,
    });
    assert.equal(foreignRead.status, 404);
    assert.equal(foreignRead.json.error.code, "job_not_found");

    const foreignCancel = await send({
      port: appPort,
      method: "POST",
      path: `${analysis.json.location}/cancel`,
      headers: { "X-PlanScope-Request": "1" },
    });
    assert.equal(foreignCancel.status, 404);

    const ownerCancel = await send({
      port: appPort,
      method: "POST",
      path: `${analysis.json.location}/cancel`,
      headers: {
        "X-PlanScope-Request": "1",
        Cookie: ownerCookie,
      },
    });
    assert.equal(ownerCancel.status, 200);

    const terminalEvents = await withTimeout(
      terminalEventsPromise,
      2_000,
      "终态事件流没有自动关闭。",
    );
    assert.equal(terminalEvents.status, 200);
    assert.match(terminalEvents.text, /"status":"cancelled"/);

    const adminLogin = await send({
      port: appPort,
      method: "POST",
      path: "/api/admin/login",
      headers: jsonHeaders(ownerCookie),
      body: JSON.stringify({ password: ADMIN_PASSWORD }),
    });
    assert.equal(adminLogin.status, 200);
    const adminCookie = cookieByName(
      adminLogin.headers["set-cookie"],
      "planscope_admin",
    );
    const history = await waitForHistory(
      appPort,
      `${ownerCookie}; ${adminCookie}`,
    );
    assert.equal(history.status, 200);
    assert.equal(
      history.json.records[0].domain,
      `localhost:${mockPort}`,
    );
    assert.ok(
      ["completed", "cancelled"].includes(
        history.json.records[0].status,
      ),
    );
    assert.doesNotMatch(history.text, /sk-test-local/);
    assert.doesNotMatch(history.text, /apiKey/);

    const upstreamLogs = await send({
      port: appPort,
      path: "/api/admin/request-logs?q=%2Fv1%2Fresponses",
      headers: { Cookie: `${ownerCookie}; ${adminCookie}` },
    });
    assert.equal(upstreamLogs.status, 200);
    assert.ok(upstreamLogs.json.records.length >= 1);
    const upstreamFailure = upstreamLogs.json.records.find(
      (record) =>
        record.scope === "upstream" &&
        record.sampleIndex === 1,
    );
    assert.ok(upstreamFailure);
    assert.equal(upstreamFailure.domain, `localhost:${mockPort}`);
    assert.equal(upstreamFailure.sampleIndex, 1);
    assert.equal(upstreamFailure.attempt, 1);
    assert.equal(upstreamFailure.responseDetail.status, 503);
    assert.match(
      upstreamFailure.responseDetail.body,
      /\[REDACTED\]/,
    );
    assert.doesNotMatch(upstreamLogs.text, /sk-test-local/);
    assert.doesNotMatch(
      upstreamLogs.text,
      /authorization|cookie|apiKey/i,
    );

    console.log(
      JSON.stringify({
        ownerRead: ownerRead.status,
        foreignRead: foreignRead.status,
        foreignCancel: foreignCancel.status,
        ownerCancel: ownerCancel.status,
        terminalStreamClosed: terminalEvents.status,
        historyRecord: history.status,
        historyDomain: history.json.records[0].domain,
        upstreamFailureLog: upstreamLogs.status,
      }),
    );
  } finally {
    app.kill("SIGTERM");
    mock.kill("SIGTERM");
    await Promise.all([waitForExit(app), waitForExit(mock)]);
  }
}

async function waitForHistory(port, cookie) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const response = await send({
      port,
      path: "/api/admin/history?limit=10",
      headers: { Cookie: cookie },
    });
    if (response.json?.records?.length > 0) return response;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("等待分析历史写入超时。");
}

async function waitForFirstSample(port, path, cookie) {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const response = await send({
      port,
      path,
      headers: { Cookie: cookie },
    });
    if (
      ["classified", "unknown", "failed"].includes(
        response.json?.samples?.[0]?.status,
      )
    ) {
      return response;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("等待首个流式 Responses 样本完成超时。");
}

async function withTimeout(promise, milliseconds, message) {
  let timeout;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timeout = setTimeout(
          () => reject(new Error(message)),
          milliseconds,
        );
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

function waitForReady(process) {
  return waitForOutput(process, "Codex PlanScope 已启动");
}

function waitForOutput(process, phrase) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("安全集成测试服务启动超时。"));
    }, 5_000);
    const onData = (chunk) => {
      if (!String(chunk).includes(phrase)) return;
      clearTimeout(timeout);
      process.stdout.off("data", onData);
      resolve();
    };
    process.stdout.on("data", onData);
    process.once("error", reject);
    process.once("exit", (code) => {
      if (code !== null) {
        clearTimeout(timeout);
        reject(
          new Error(`安全集成测试服务提前退出：${code}`),
        );
      }
    });
  });
}

function jsonHeaders(cookie) {
  return {
    "X-PlanScope-Request": "1",
    "Content-Type": "application/json",
    Cookie: cookie,
  };
}

function waitForExit(process) {
  if (process.exitCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      process.kill("SIGKILL");
      resolve();
    }, 2_000);
    process.once("exit", () => {
      clearTimeout(timeout);
      resolve();
    });
  });
}

function cookiePair(setCookie) {
  return String(setCookie).split(";")[0];
}

function cookieByName(setCookies, name) {
  const values = Array.isArray(setCookies)
    ? setCookies
    : [setCookies];
  const match = values
    .map(cookiePair)
    .find((cookie) => cookie.startsWith(`${name}=`));
  assert.ok(match, `缺少 ${name} Cookie`);
  return match;
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
