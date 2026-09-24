"use strict";

// Local backend using public threat-intelligence feeds; no sample verdicts are generated.
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const HOST = "127.0.0.1";
const PORT = Number(process.env.PORT || 8787);
const MAX_BODY_BYTES = 1024 * 1024;
const OPENPHISH_FEED_URL = "https://openphish.com/feed.txt";
const OPENPHISH_REFRESH_MS = 6 * 60 * 60 * 1000;
const URLHAUS_LOOKUP_URL = "https://urlhaus-api.abuse.ch/v1/url/";
let openPhishSnapshot = null;
let openPhishFetchedAt = 0;
let openPhishRefreshPromise = null;

// Load optional KEY=value settings from backend/.env without an extra package.
function loadEnvFile() {
  const envPath = path.join(__dirname, ".env");
  if (!fs.existsSync(envPath)) return;

  for (const sourceLine of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const line = sourceLine.trim();
    if (!line || line.startsWith("#")) continue;

    const separator = line.indexOf("=");
    if (separator < 1) continue;

    const name = line.slice(0, separator).trim();
    let value = line.slice(separator + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!process.env[name]) process.env[name] = value;
  }
}

loadEnvFile();

// Allow browser calls only from a Chrome extension; requests without Origin are for local tools.
function setCorsHeaders(req, res) {
  const origin = req.headers.origin;
  if (!origin) return true;
  if (!/^chrome-extension:\/\/[a-p]{32}$/.test(origin)) return false;

  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "600");
  return true;
}

// Send JSON responses consistently to the extension popup.
function sendJson(res, statusCode, body) {
  const encoded = JSON.stringify(body);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(encoded),
    "Cache-Control": "no-store"
  });
  res.end(encoded);
}

// Read and parse a bounded JSON request body.
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let byteLength = 0;
    const chunks = [];

    req.on("data", (chunk) => {
      byteLength += chunk.length;
      if (byteLength > MAX_BODY_BYTES) {
        reject(Object.assign(new Error("Request body is too large."), { statusCode: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      try {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve(text ? JSON.parse(text) : {});
      } catch {
        reject(Object.assign(new Error("Request body must contain valid JSON."), { statusCode: 400 }));
      }
    });

    req.on("error", reject);
  });
}

// Keep only the tab fields required by the popup and validate each URL.
function validateTabs(tabs) {
  if (!Array.isArray(tabs)) throw Object.assign(new Error("Request must contain a tabs array."), { statusCode: 400 });

  return tabs.map((tab) => {
    if (!tab || !Number.isInteger(tab.id) || typeof tab.title !== "string" || typeof tab.url !== "string") {
      throw Object.assign(new Error("Each tab must include numeric id, string title, and string url."), { statusCode: 400 });
    }

    const url = normalizeUrl(tab.url);
    return { id: tab.id, title: tab.title, url };
  });
}

// Canonicalize URLs the same way for incoming tabs and the downloaded feed.
function normalizeUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw Object.assign(new Error("A tab contains an invalid URL."), { statusCode: 400 });
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw Object.assign(new Error("Only HTTP and HTTPS URLs can be analyzed."), { statusCode: 400 });
  }
  parsed.hash = "";
  return parsed.href;
}

// Download and cache OpenPhish's public text feed; refresh it every six hours.
async function getOpenPhishSnapshot() {
  if (openPhishSnapshot && Date.now() - openPhishFetchedAt < OPENPHISH_REFRESH_MS) {
    return openPhishSnapshot;
  }
  if (openPhishRefreshPromise) return openPhishRefreshPromise;

  openPhishRefreshPromise = (async () => {
    const response = await fetch(OPENPHISH_FEED_URL, { headers: { accept: "text/plain" } });
    if (!response.ok) throw Object.assign(new Error(`OpenPhish feed returned HTTP ${response.status}.`), { statusCode: 503 });

    const text = await response.text();
    const entries = text.split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#"))
      .map((line) => {
        try { return normalizeUrl(line); } catch { return null; }
      })
      .filter(Boolean);

    if (!entries.length) throw Object.assign(new Error("OpenPhish feed returned no usable URLs."), { statusCode: 503 });
    openPhishSnapshot = new Set(entries);
    openPhishFetchedAt = Date.now();
    return openPhishSnapshot;
  })();

  try {
    return await openPhishRefreshPromise;
  } finally {
    openPhishRefreshPromise = null;
  }
}

// Optional exact-URL lookup in URLhaus; its free Auth-Key remains on the backend.
async function lookupUrlhaus(url) {
  const authKey = process.env.URLHAUS_AUTH_KEY?.trim();
  if (!authKey) return null;

  const response = await fetch(URLHAUS_LOOKUP_URL, {
    method: "POST",
    headers: {
      accept: "application/json",
      "Auth-Key": authKey,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({ url })
  });
  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message = payload.error || `URLhaus returned HTTP ${response.status}.`;
    throw Object.assign(new Error(message), { statusCode: response.status === 429 ? 429 : 502 });
  }
  if (payload.query_status === "ok") return payload;
  if (payload.query_status === "no_results") return null;
  throw Object.assign(new Error(`URLhaus query status: ${payload.query_status || "unknown"}.`), { statusCode: 502 });
}

// Analyze one tab against the real feed snapshots and return the popup's data contract.
async function analyzeTab(tab, openPhishSnapshot) {
  const evidence = [];

  // OpenPhish contributes evidence only when the normalized full URL is listed.
  if (openPhishSnapshot.has(tab.url)) {
    evidence.push("OpenPhish public feed: exact URL match.");
  }

  // If URLhaus is configured, query it as a second independent malware-URL source.
  const urlhausResult = await lookupUrlhaus(tab.url);
  if (urlhausResult) {
    const descriptors = [urlhausResult.threat, urlhausResult.url_status].filter(Boolean);
    const tags = Array.isArray(urlhausResult.tags) && urlhausResult.tags.length
      ? `; tags: ${urlhausResult.tags.join(", ")}`
      : "";
    evidence.push(`URLhaus listing${descriptors.length ? ` (${descriptors.join(", ")})` : ""}${tags}.`);
  }

  // This is a binary feed-match indicator, not a probability or machine-learning score.
  const matched = evidence.length > 0;
  return {
    ...tab,
    status: matched ? "malicious" : "safe",
    riskScore: matched ? 100 : 0,
    evidence
  };
}

// Serve health checks and tab analysis requests from the Chrome extension popup.
const server = http.createServer(async (req, res) => {
  if (!setCorsHeaders(req, res)) {
    sendJson(res, 403, { error: "Origin is not allowed." });
    return;
  }

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const requestUrl = new URL(req.url, `http://${HOST}:${PORT}`);
  if (req.method === "GET" && requestUrl.pathname === "/health") {
    sendJson(res, 200, {
      ok: true,
      sources: ["OpenPhish", ...(process.env.URLHAUS_AUTH_KEY ? ["URLhaus"] : [])],
      openPhishLoaded: Boolean(openPhishSnapshot),
      openPhishFetchedAt: openPhishFetchedAt ? new Date(openPhishFetchedAt).toISOString() : null,
      urlhausEnabled: Boolean(process.env.URLHAUS_AUTH_KEY)
    });
    return;
  }

  if (req.method !== "POST" || requestUrl.pathname !== "/api/analyze") {
    sendJson(res, 404, { error: "Route not found." });
    return;
  }

  try {
    const body = await readJsonBody(req);
    const tabs = validateTabs(body.tabs);
    const openPhishSnapshot = await getOpenPhishSnapshot();

    // Process sequentially so an optional API lookup does not flood the source.
    const results = [];
    for (const tab of tabs) results.push(await analyzeTab(tab, openPhishSnapshot));
    sendJson(res, 200, { tabs: results });
  } catch (error) {
    sendJson(res, error.statusCode || 502, { error: error.message || "Threat feed lookup failed." });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`PhishGuard backend listening at http://${HOST}:${PORT}`);
  // Warm the feed cache in the background; requests also await a refresh if needed.
  getOpenPhishSnapshot()
    .then((snapshot) => console.log(`Loaded ${snapshot.size} OpenPhish URLs.`))
    .catch((error) => console.error(`Could not load OpenPhish feed: ${error.message}`));
});
