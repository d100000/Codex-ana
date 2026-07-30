import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { request } from "node:http";
import { fileURLToPath } from "node:url";

const ROOT_DIR = fileURLToPath(new URL("..", import.meta.url));
const PORT = Number(process.env.INTEGRATION_PORT || 4397);
const child = spawn(process.execPath, ["server.mjs"], {
  cwd: ROOT_DIR,
  env: {
    ...process.env,
    HOST: "127.0.0.1",
    PORT: String(PORT),
    ALLOW_HTTP_UPSTREAMS: "",
    ALLOW_PRIVATE_UPSTREAMS: "",
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
    }),
  );
} finally {
  child.kill("SIGTERM");
  await waitForExit(child);
}

await verifyJobOwnership();

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

    const ownerRead = await send({
      port: appPort,
      path: analysis.json.location,
      headers: { Cookie: ownerCookie },
    });
    assert.equal(ownerRead.status, 200);

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

    console.log(
      JSON.stringify({
        ownerRead: ownerRead.status,
        foreignRead: foreignRead.status,
        foreignCancel: foreignCancel.status,
        ownerCancel: ownerCancel.status,
      }),
    );
  } finally {
    app.kill("SIGTERM");
    mock.kill("SIGTERM");
    await Promise.all([waitForExit(app), waitForExit(mock)]);
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

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
