import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import {
  createSafeFetch,
  isPublicAddress,
  resolveSafeTarget,
  UpstreamSecurityError,
} from "../src/safe-fetch.mjs";

test("public address classifier blocks internal and special networks", () => {
  for (const address of [
    "0.0.0.0",
    "10.1.2.3",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "192.168.1.1",
    "198.51.100.3",
    "::1",
    "fc00::1",
    "fe80::1",
    "2001:db8::1",
    "::7f00:1",
  ]) {
    assert.equal(isPublicAddress(address), false, address);
  }
  assert.equal(isPublicAddress("8.8.8.8"), true);
  assert.equal(isPublicAddress("2606:4700:4700::1111"), true);
});

test("upstream policy defaults to HTTPS and public DNS results", async () => {
  await assert.rejects(
    resolveSafeTarget("http://gateway.example/v1", {
      resolver: publicResolver,
    }),
    (error) =>
      error instanceof UpstreamSecurityError &&
      error.code === "insecure_upstream_protocol",
  );
  await assert.rejects(
    resolveSafeTarget("https://gateway.example/v1", {
      resolver: async () => [
        { address: "93.184.216.34", family: 4 },
        { address: "127.0.0.1", family: 4 },
      ],
    }),
    (error) => error.code === "private_upstream_blocked",
  );
  await assert.rejects(
    resolveSafeTarget("https://2130706433/v1"),
    (error) => error.code === "private_upstream_blocked",
  );

  const target = await resolveSafeTarget(
    "https://gateway.example/v1",
    {
      resolver: publicResolver,
    },
  );
  assert.equal(target.selectedAddress.address, "93.184.216.34");
});

test("upstream allowlists reject unexpected hosts and ports", async () => {
  await assert.rejects(
    resolveSafeTarget("https://other.example/v1", {
      allowedHosts: ["gateway.example"],
      resolver: publicResolver,
    }),
    (error) => error.code === "upstream_host_not_allowed",
  );
  await assert.rejects(
    resolveSafeTarget("https://gateway.example:8443/v1", {
      resolver: publicResolver,
    }),
    (error) => error.code === "upstream_port_not_allowed",
  );
});

test("DNS resolution has a hard deadline", async () => {
  await assert.rejects(
    resolveSafeTarget("https://slow.example/v1", {
      dnsTimeoutMs: 250,
      resolver: () => new Promise(() => {}),
    }),
    (error) => error.code === "upstream_dns_timeout",
  );
});

test("safe fetch pins the validated address and never follows redirects", async (t) => {
  let requestCount = 0;
  const pinnedAddresses = [];
  const transport = fakeTransport((url, options) => {
    requestCount += 1;
    options.lookup(url.hostname, {}, (error, address, family) => {
      assert.ifError(error);
      pinnedAddresses.push({ address, family });
    });
    if (url.pathname === "/redirect") {
      return {
        status: 302,
        headers: {
          Location: "http://169.254.169.254/latest/meta-data",
        },
      };
    }
    return {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: url.pathname }),
    };
  });

  const safeFetch = createSafeFetch({
    allowHttp: true,
    allowPrivateNetworks: true,
    allowedPorts: [8_080],
    httpRequest: transport,
    resolver: async (hostname) => {
      assert.equal(hostname, "pinned.example");
      return [{ address: "127.0.0.1", family: 4 }];
    },
  });

  const response = await safeFetch(
    "http://pinned.example:8080/models",
    { redirect: "manual" },
  );
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { path: "/models" });

  const redirect = await safeFetch(
    "http://pinned.example:8080/redirect",
    { redirect: "manual" },
  );
  assert.equal(redirect.status, 302);
  assert.equal(requestCount, 2);
  assert.deepEqual(pinnedAddresses, [
    { address: "127.0.0.1", family: 4 },
    { address: "127.0.0.1", family: 4 },
  ]);
});

test("safe fetch caps untrusted upstream response bodies", async (t) => {
  const safeFetch = createSafeFetch({
    allowHttp: true,
    allowPrivateNetworks: true,
    allowedPorts: [8_080],
    maxResponseBytes: 1_024,
    httpRequest: fakeTransport(() => ({
      status: 200,
      headers: { "Content-Type": "text/plain" },
      body: "x".repeat(2_048),
    })),
    resolver: async () => [
      { address: "127.0.0.1", family: 4 },
    ],
  });

  await assert.rejects(
    safeFetch("http://limit.example:8080/large", {
      redirect: "manual",
    }),
    (error) => error.code === "upstream_response_too_large",
  );
});

async function publicResolver() {
  return [{ address: "93.184.216.34", family: 4 }];
}

function fakeTransport(createResponse) {
  return (url, options) => {
    const request = new EventEmitter();
    request.write = () => {};
    request.destroy = (error) => {
      if (error) queueMicrotask(() => request.emit("error", error));
    };
    request.end = () => {
      queueMicrotask(() => {
        const definition = createResponse(url, options);
        const incoming = new EventEmitter();
        incoming.statusCode = definition.status ?? 200;
        incoming.rawHeaders = Object.entries(
          definition.headers ?? {},
        ).flatMap(([name, value]) => [name, String(value)]);
        incoming.destroy = (error) => {
          if (error) {
            queueMicrotask(() => incoming.emit("error", error));
          }
        };
        request.emit("response", incoming);
        if (definition.body) {
          incoming.emit("data", Buffer.from(definition.body));
        }
        incoming.emit("end");
      });
    };
    return request;
  };
}
