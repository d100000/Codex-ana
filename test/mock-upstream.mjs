import { createServer } from "node:http";

const HOST = "127.0.0.1";
const PORT = Number(process.env.MOCK_PORT || 4318);
const EXPECTED_KEY = "sk-test-local";
const attempts = new Map();

const server = createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host}`);
  if (request.headers.authorization !== `Bearer ${EXPECTED_KEY}`) {
    sendJson(response, 401, { error: { message: "Invalid test key" } });
    return;
  }

  if (request.method === "GET" && url.pathname === "/v1/models") {
    sendJson(response, 200, {
      object: "list",
      data: [{ id: "gpt-5.4-mini", object: "model" }],
    });
    return;
  }

  if (request.method === "POST" && url.pathname === "/v1/responses") {
    const body = await readJson(request);
    const index = readSampleIndex(body?.prompt_cache_key);
    if (index === null) {
      sendJson(response, 400, {
        error: { message: "Missing PlanScope sample index" },
      });
      return;
    }

    const attempt = (attempts.get(index) || 0) + 1;
    attempts.set(index, attempt);
    if ([22, 45, 68, 91].includes(index) && attempt === 1) {
      sendJson(response, 503, {
        error: { message: "Mock transient overload; retry expected" },
      });
      return;
    }

    await new Promise((resolve) =>
      setTimeout(resolve, 38 + ((index * 17) % 85)),
    );
    const tier = tierForIndex(index);
    const headers = {
      "x-request-id": `mock_req_${String(index + 1).padStart(3, "0")}_${attempt}`,
      "x-codex-active-limit": tier === "free" ? "standard" : "premium",
      "x-codex-primary-used-percent": String((index * 7) % 96),
      "x-codex-primary-window-minutes": tier === "free" ? "300" : "10080",
      "x-codex-primary-reset-at": String(
        Math.floor(Date.now() / 1_000) + 3_600,
      ),
      "x-codex-credits-has-credits": tier === "free" ? "false" : "true",
      "x-codex-credits-unlimited": tier === "business" ? "true" : "false",
    };
    if (tier) headers["x-codex-plan-type"] = tier;

    sendJson(
      response,
      200,
      {
        id: `resp_mock_${index}`,
        object: "response",
        model: body.model,
        output: [],
      },
      headers,
    );
    return;
  }

  sendJson(response, 404, { error: { message: "Not found" } });
});

server.listen(PORT, HOST, () => {
  console.log(`PlanScope 模拟上游：http://${HOST}:${PORT}`);
  console.log(`测试 Key：${EXPECTED_KEY}`);
  console.log(
    "动态分布：Pro 30 / Plus 20 / Team 15 / K12 15 / Partner Alpha 10 / Enterprise Custom 5 / Unknown 5",
  );
});

function tierForIndex(index) {
  if (index < 30) return "pro";
  if (index < 50) return "plus";
  if (index < 65) return "team";
  if (index < 80) return "k12";
  if (index < 90) return "partner_alpha";
  if (index < 95) return "enterprise_custom";
  return null;
}

function readSampleIndex(value) {
  const match = String(value || "").match(/^plan-probe-(\d+)-/);
  return match ? Number(match[1]) : null;
}

async function readJson(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

function sendJson(response, status, payload, headers = {}) {
  response.writeHead(status, {
    "Content-Type": "application/json",
    ...headers,
  });
  response.end(JSON.stringify(payload));
}

function shutdown() {
  server.close(() => process.exit(0));
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
