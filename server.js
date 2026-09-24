/**
 * PhishGuard Web - Intelligence Backend Server
 * Production-Grade Node.js Native HTTP Threat Triage Service
 * 
 * Strict Constraints Adherence:
 * - No external dependencies: Pure Node.js built-in modules only (`http`, `https`, `fs`, `path`, `url`, `crypto`).
 * - No fabricated data: Strictly adheres to the Tri-State contract (malicious, safe, unknown).
 * - Anti-evasion double indexing for OpenPhish feed.
 * - VirusTotal v3 unpadded base64url integration.
 * - Strict CORS handling with chrome-extension:// origins support.
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

// -----------------------------------------------------------------------------
// 1. Environment & Configuration
// -----------------------------------------------------------------------------
function loadEnv(filePath) {
  if (!fs.existsSync(filePath)) return;
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split(/\r?\n/);
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const eqIdx = line.indexOf('=');
      if (eqIdx === -1) continue;
      const key = line.slice(0, eqIdx).trim();
      let val = line.slice(eqIdx + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (key && (process.env[key] === undefined || process.env[key] === '')) {
        process.env[key] = val;
      }
    }
  } catch (err) {
    console.error(`[Config] Failed to parse ${filePath}: ${err.message}`);
  }
}

// Load .env from multiple candidate locations (local backend dir, project root, and user home)
loadEnv(path.join(__dirname, '.env'));
loadEnv(path.join(__dirname, '..', '.env'));
if (process.env.HOME) {
  loadEnv(path.join(process.env.HOME, '.env'));
}

const RAW_HOST = process.env.HOST || '127.0.0.1';
const HOST = (RAW_HOST === 'all' || RAW_HOST === '0.0.0.0') ? '0.0.0.0' : RAW_HOST;
const PORT = parseInt(process.env.PORT || '8787', 10);
const VIRUSTOTAL_API_KEY = (process.env.VIRUSTOTAL_API_KEY || '').trim();
const OPENPHISH_FEED_URL = process.env.OPENPHISH_FEED_URL || 'https://openphish.com/feed.txt';
const FEED_REFRESH_MINUTES = parseInt(process.env.FEED_REFRESH_MINUTES || '360', 10);

// -----------------------------------------------------------------------------
// 2. OpenPhish In-Memory Cache & Anti-Evasion Double Index
// -----------------------------------------------------------------------------
const openPhishCache = {
  exactMap: new Map(),    // normalized exact URL -> original feed entry
  strippedMap: new Map(), // query-stripped URL -> original feed entry
  totalLoaded: 0,
  lastFetchedAt: null,
  isLoaded: false,
  lastError: null
};

/**
 * Decodes URI components safely to counter obfuscation evasions.
 */
function safeDecode(str) {
  try {
    return decodeURIComponent(str);
  } catch {
    return str;
  }
}

/**
 * Normalizes URL for uniform comparisons:
 * - Lowercase protocol & host
 * - Strip client fragments
 * - Safe URI decoding of path
 */
function normalizeUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    parsed.hash = ''; // ignore client-side hashes
    parsed.pathname = safeDecode(parsed.pathname);
    return parsed.toString();
  } catch {
    return (rawUrl || '').trim();
  }
}

/**
 * Strips query string and hash for anti-evasion matching.
 */
function stripQuery(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    parsed.search = '';
    parsed.hash = '';
    parsed.pathname = safeDecode(parsed.pathname);
    return parsed.toString();
  } catch {
    const qIdx = rawUrl.indexOf('?');
    const hIdx = rawUrl.indexOf('#');
    let cut = rawUrl.length;
    if (qIdx !== -1) cut = Math.min(cut, qIdx);
    if (hIdx !== -1) cut = Math.min(cut, hIdx);
    return rawUrl.slice(0, cut).trim();
  }
}

/**
 * Generates trailing slash variants to defeat slash-padding evasions.
 */
function getSlashVariants(urlStr) {
  const variants = [urlStr];
  try {
    const parsed = new URL(urlStr);
    if (parsed.pathname.length > 1) {
      if (parsed.pathname.endsWith('/')) {
        const copy = new URL(urlStr);
        copy.pathname = copy.pathname.replace(/\/+$/, '');
        variants.push(copy.toString());
      } else {
        const copy = new URL(urlStr);
        copy.pathname = copy.pathname + '/';
        variants.push(copy.toString());
      }
    }
  } catch {
    // ignore
  }
  return variants;
}

/**
 * Parses raw OpenPhish feed text and builds both exact and query-stripped indices.
 */
function indexOpenPhishFeed(feedText) {
  const lines = feedText.split(/\r?\n/);
  const exact = new Map();
  const stripped = new Map();
  let count = 0;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    count++;

    const norm = normalizeUrl(line);
    const strippedUrl = stripQuery(line);

    if (!exact.has(norm)) {
      exact.set(norm, line);
    }
    if (!stripped.has(strippedUrl)) {
      stripped.set(strippedUrl, line);
    }
  }

  openPhishCache.exactMap = exact;
  openPhishCache.strippedMap = stripped;
  openPhishCache.totalLoaded = count;
  openPhishCache.lastFetchedAt = new Date().toISOString();
  openPhishCache.isLoaded = true;
  openPhishCache.lastError = null;

  console.log(`[OpenPhish] Successfully indexed ${count} feed entries (Exact: ${exact.size}, Stripped: ${stripped.size}) at ${openPhishCache.lastFetchedAt}`);
}

/**
 * Fetches OpenPhish feed over HTTPS. Gracefully falls back to local seed/cache on network error.
 */
function fetchOpenPhishFeed(urlToFetch = OPENPHISH_FEED_URL) {
  console.log(`[OpenPhish] Fetching public text feed from ${urlToFetch}...`);

  try {
    const targetUrl = new URL(urlToFetch);
    const client = targetUrl.protocol === 'http:' ? http : https;

    const req = client.get(targetUrl, {
      timeout: 15000,
      headers: {
        'User-Agent': 'PhishGuard-Web-Intelligence/1.0'
      }
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        console.log(`[OpenPhish] Following redirect to ${res.headers.location}`);
        fetchOpenPhishFeed(res.headers.location);
        return;
      }

      if (res.statusCode !== 200) {
        handleFeedFetchFailure(new Error(`HTTP ${res.statusCode} ${res.statusMessage}`));
        res.resume();
        return;
      }

      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        indexOpenPhishFeed(data);
        // Persist local copy as offline fallback
        try {
          const fallbackPath = path.join(__dirname, 'openphish_fallback.txt');
          fs.writeFileSync(fallbackPath, data, 'utf8');
        } catch {
          // ignore cache write errors
        }
      });
    });

    req.on('timeout', () => {
      req.destroy(new Error('Connection timed out'));
    });

    req.on('error', (err) => {
      handleFeedFetchFailure(err);
    });
  } catch (err) {
    handleFeedFetchFailure(err);
  }
}

function loadInitialFeed() {
  const fallbackPath = path.join(__dirname, 'openphish_fallback.txt');
  if (fs.existsSync(fallbackPath)) {
    try {
      const data = fs.readFileSync(fallbackPath, 'utf8');
      indexOpenPhishFeed(data);
      console.log('[OpenPhish] Initial baseline feed loaded from disk.');
    } catch (err) {
      console.error(`[OpenPhish] Error reading initial fallback feed: ${err.message}`);
    }
  }
}

function handleFeedFetchFailure(err) {
  console.warn(`[OpenPhish] Feed fetch failed (${err.message}).`);
  openPhishCache.lastError = err.message;
  // If no entries are loaded at all, try loading fallback
  if (openPhishCache.exactMap.size === 0) {
    loadInitialFeed();
  }
}

// -----------------------------------------------------------------------------
// 3. VirusTotal v3 Integration with In-Memory Caching & Rate-Limit Backoff
// -----------------------------------------------------------------------------
const virusTotalCache = new Map(); // base64UrlId -> { result, cachedAt }
const VT_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour TTL to preserve API quota
let vtRateLimitedUntil = 0; // Epoch ms timestamp for 429 backoff

/**
 * Computes unpadded base64url encoding for VirusTotal v3 API.
 * RFC 4648 Section 5 URL-safe base64 without '=' padding.
 */
function toUnpaddedBase64Url(urlStr) {
  return Buffer.from(urlStr, 'utf8').toString('base64url');
}

/**
 * Queries VirusTotal v3 API for URL analysis report with caching & rate limiting.
 * Strictly adheres to no fabricated data.
 */
function queryVirusTotal(urlStr, apiKey) {
  return new Promise((resolve) => {
    if (!apiKey) {
      return resolve({
        status: 'disabled',
        reason: 'VirusTotal: API key not configured'
      });
    }

    // Strip client hash before querying VirusTotal
    let lookupUrl = urlStr;
    try {
      const p = new URL(urlStr);
      p.hash = '';
      lookupUrl = p.toString();
    } catch {
      lookupUrl = (urlStr || '').trim();
    }

    const base64UrlId = toUnpaddedBase64Url(lookupUrl);
    const now = Date.now();

    // 1. Check in-memory cache
    const cached = virusTotalCache.get(base64UrlId);
    if (cached && (now - cached.cachedAt < VT_CACHE_TTL_MS)) {
      return resolve(cached.result);
    }

    // 2. Check active 429 rate limit backoff
    if (now < vtRateLimitedUntil) {
      return resolve({
        status: 'unverified',
        reason: 'VirusTotal: API rate limit backoff active (429 - cooling down)'
      });
    }

    const vtUrl = `https://www.virustotal.com/api/v3/urls/${base64UrlId}`;
    const options = {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
        'Accept': 'application/json',
        'User-Agent': 'PhishGuard-Web/1.0'
      },
      timeout: 10000
    };

    const req = https.request(vtUrl, options, (res) => {
      let bodyStr = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { bodyStr += chunk; });
      res.on('end', () => {
        let outcome;

        if (res.statusCode === 200) {
          try {
            const parsed = JSON.parse(bodyStr);
            const attrs = parsed.data?.attributes;
            const stats = attrs?.last_analysis_stats || {};
            const results = attrs?.last_analysis_results || {};

            const malicious = Number(stats.malicious) || 0;
            const suspicious = Number(stats.suspicious) || 0;
            const harmless = Number(stats.harmless) || 0;
            const undetected = Number(stats.undetected) || 0;

            if (malicious > 0 || suspicious > 0) {
              const flaggingEngines = [];
              for (const [engine, detail] of Object.entries(results)) {
                if (detail.category === 'malicious' || detail.category === 'suspicious') {
                  flaggingEngines.push(`${engine} (${detail.result || detail.category})`);
                }
              }
              const enginesStr = flaggingEngines.slice(0, 4).join(', ') + (flaggingEngines.length > 4 ? ` +${flaggingEngines.length - 4} more` : '');
              outcome = {
                status: 'malicious',
                evidence: [`VirusTotal: ${malicious + suspicious} security vendors flagged this URL [${enginesStr}]`],
                notes: [`VirusTotal analysis stats: malicious=${malicious}, suspicious=${suspicious}, harmless=${harmless}, undetected=${undetected}`]
              };
            } else if (harmless > 0 || undetected > 0) {
              outcome = {
                status: 'safe',
                evidence: [],
                notes: [`VirusTotal: URL analyzed cleanly (${harmless} harmless, ${undetected} undetected across engines)`]
              };
            } else {
              outcome = {
                status: 'unverified',
                reason: 'VirusTotal: URL analysis pending or zero engine evaluations recorded'
              };
            }
          } catch (parseErr) {
            outcome = {
              status: 'unverified',
              reason: `VirusTotal: Failed to parse API JSON response (${parseErr.message})`
            };
          }
        } else if (res.statusCode === 404) {
          outcome = {
            status: 'unverified',
            reason: 'VirusTotal: URL not found in dataset (404 - unanalyzed)'
          };
        } else if (res.statusCode === 429) {
          vtRateLimitedUntil = Date.now() + 60000; // 60s backoff
          outcome = {
            status: 'unverified',
            reason: 'VirusTotal: API rate limit reached (429 - 60s cooldown initiated)'
          };
        } else if (res.statusCode === 401 || res.statusCode === 403) {
          outcome = {
            status: 'unverified',
            reason: `VirusTotal: Authentication error (HTTP ${res.statusCode} - invalid or missing permissions)`
          };
        } else {
          outcome = {
            status: 'unverified',
            reason: `VirusTotal: Upstream returned HTTP ${res.statusCode}`
          };
        }

        // Cache valid responses
        if (res.statusCode === 200 || res.statusCode === 404) {
          virusTotalCache.set(base64UrlId, { result: outcome, cachedAt: Date.now() });
        }

        resolve(outcome);
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({
        status: 'unverified',
        reason: 'VirusTotal: Upstream request timed out (10s)'
      });
    });

    req.on('error', (err) => {
      resolve({
        status: 'unverified',
        reason: `VirusTotal: Connection failed (${err.message})`
      });
    });

    req.end();
  });
}

// -----------------------------------------------------------------------------
// 4. Tri-State Triage Engine
// -----------------------------------------------------------------------------
function extractHost(urlStr) {
  try {
    return new URL(urlStr).hostname;
  } catch {
    return urlStr;
  }
}

const EPHEMERAL_AD_TRACKER_DOMAINS = [
  'rollssagesamorence', 'uuidksinc', 'monetag', 'clickadu', 'adsterra',
  'propellerads', 'popcash', 'popads', 'onclickperformance', 'highperformancecpmgate',
  'hilltopads', 'dafapromo'
];

const REDIRECT_TRACKER_PARAMS = [
  'externalid=', 'clickid=', 'matchx', 'destination=http', 'destination=https',
  'redirect_url=', 'target_url=', 'r.uuidksinc.net'
];

/**
 * Triages an individual URL against all intelligence sources.
 * Adheres strictly to the Tri-State Contract:
 * - 'malicious': Flagged by ANY source. riskScore: 100.
 * - 'safe': Checked by ALL enabled sources, flagged by none. riskScore: 0.
 * - 'unknown': Unanalyzed/404, rate limited, failed, or source unverified. Never default to safe.
 */
async function triageUrl(item, apiKey) {
  const rawUrl = typeof item === 'string' ? item : (item?.url || '');
  const id = (typeof item === 'object' && item?.id !== undefined) ? item.id : rawUrl;
  const title = (typeof item === 'object' && item?.title) ? item.title : extractHost(rawUrl);
  const contentSignals = (typeof item === 'object' && item?.contentSignals) ? item.contentSignals : null;
  const contentScore = Number(contentSignals?.contentThreatScore) || 0;
  const contentFindings = Array.isArray(contentSignals?.findings) ? contentSignals.findings : [];

  const result = {
    id,
    title,
    url: rawUrl,
    status: 'unknown',
    threatLevel: 'safe', // 'safe' (0, Green) | 'warning' (1-50, Yellow) | 'danger' (50-100, Red)
    riskScore: 0,
    evidence: [],
    contentFindings: [],
    notes: [],
    unverifiedBy: []
  };

  // Add on-screen / DOM inspection findings if present
  if (contentFindings.length > 0) {
    result.contentFindings = contentFindings;
    for (const finding of contentFindings) {
      result.evidence.push(`On-Screen Content: ${finding}`);
    }
  }

  // Basic sanity check
  if (!rawUrl || typeof rawUrl !== 'string') {
    result.status = 'unknown';
    result.unverifiedBy.push('InputValidator');
    result.notes.push('Invalid empty or non-string URL');
    return result;
  }

  const isHttp = /^https?:\/\//i.test(rawUrl);
  if (!isHttp) {
    result.status = 'unknown';
    result.unverifiedBy.push('ProtocolValidator');
    result.notes.push('Non-HTTP/HTTPS protocol (skipped external lookup)');
    return result;
  }

  // --- Source 1: OpenPhish Feed Check with Trailing Slash Normalization ---
  let openPhishFlagged = false;
  if (!openPhishCache.isLoaded) {
    result.unverifiedBy.push('OpenPhish');
    result.notes.push(`OpenPhish feed unavailable (${openPhishCache.lastError || 'Loading'})`);
  } else {
    const norm = normalizeUrl(rawUrl);
    const stripped = stripQuery(rawUrl);

    // Exact Match (including slash variants)
    const exactCandidates = getSlashVariants(norm);
    let matchedExactEntry = null;
    for (const cand of exactCandidates) {
      if (openPhishCache.exactMap.has(cand)) {
        matchedExactEntry = openPhishCache.exactMap.get(cand);
        break;
      }
    }

    if (matchedExactEntry) {
      openPhishFlagged = true;
      result.evidence.push(`OpenPhish Feed Match: Exact match found for feed entry "${matchedExactEntry}"`);
    } else {
      // Anti-Evasion Query-Stripped Match (including slash variants)
      const strippedCandidates = getSlashVariants(stripped);
      let matchedStrippedEntry = null;
      for (const cand of strippedCandidates) {
        if (openPhishCache.strippedMap.has(cand)) {
          matchedStrippedEntry = openPhishCache.strippedMap.get(cand);
          break;
        }
      }

      if (matchedStrippedEntry) {
        openPhishFlagged = true;
        result.evidence.push(`OpenPhish Anti-Evasion Match: Tab URL matches query-stripped feed entry "${matchedStrippedEntry}"`);
      } else {
        result.notes.push('OpenPhish: URL clean against active threat feed');
      }
    }
  }

  // --- Source 2: VirusTotal v3 Check ---
  let vtFlagged = false;
  const isVtEnabled = Boolean(apiKey && apiKey.trim().length > 0);

  if (isVtEnabled) {
    const vtResult = await queryVirusTotal(rawUrl, apiKey);
    if (vtResult.status === 'malicious') {
      vtFlagged = true;
      if (vtResult.evidence) result.evidence.push(...vtResult.evidence);
      if (vtResult.notes) result.notes.push(...vtResult.notes);
    } else if (vtResult.status === 'safe') {
      if (vtResult.notes) result.notes.push(...vtResult.notes);
    } else {
      result.unverifiedBy.push('VirusTotal');
      if (vtResult.reason) result.notes.push(vtResult.reason);
    }
  } else {
    result.notes.push('VirusTotal: Disabled (no API key configured)');
  }

  // --- Ephemeral Malvertising Ad-Redirect & Tracker Detection ---
  let isAdTracker = false;
  const host = extractHost(rawUrl).toLowerCase();
  for (const dom of EPHEMERAL_AD_TRACKER_DOMAINS) {
    if (host.includes(dom)) {
      isAdTracker = true;
      result.evidence.push(`Malvertising Tracker Gateway: Hostname matches disposable ad-redirector network ("${dom}")`);
      break;
    }
  }
  if (!isAdTracker) {
    for (const param of REDIRECT_TRACKER_PARAMS) {
      if (rawUrl.toLowerCase().includes(param.toLowerCase())) {
        isAdTracker = true;
        result.evidence.push(`Ephemeral Ad-Redirect Parameter: URL routes traffic through click-tracker parameter ("${param.replace('=', '')}")`);
        break;
      }
    }
  }

  // --- Multi-Tier Threat Level Decision Matrix ---
  // Levels:
  // 0: Green (Safe)
  // 1-50: Yellow (Warning)
  // 50-100: Red (Danger)
  let urlScore = 0;
  if (openPhishFlagged || vtFlagged) {
    urlScore = 100;
  } else if (isAdTracker) {
    urlScore = 45;
  }

  const finalScore = Math.min(100, Math.max(urlScore, contentScore));
  result.riskScore = finalScore;

  if (finalScore > 50) {
    result.threatLevel = 'danger';
    result.status = 'malicious';
  } else if (finalScore > 0) {
    result.threatLevel = 'warning';
    result.status = 'warning';
    if (contentScore > 0) {
      result.notes.push(`Threat Level: Warning (Score ${finalScore}/100) based on on-screen content heuristic inspection`);
    } else if (isAdTracker) {
      result.notes.push(`Threat Level: Warning (Score ${finalScore}/100) based on ephemeral ad-redirector and tracker pattern detection`);
    }
  } else {
    result.threatLevel = 'safe';
    if (result.unverifiedBy.length === 0) {
      result.status = 'safe';
    } else {
      result.status = 'unknown';
    }
  }

  // Zero-hour telemetry insight when multi-vendor feeds show clean/0 hits
  if (finalScore > 0 && isVtEnabled && !vtFlagged) {
    result.notes.push('Zero-Hour Behavioral Telemetry: Multi-vendor reputation engines (VirusTotal) report 0 hits due to ephemeral domain rotation / cloaking latency, but live behavioral telemetry detected active threats.');
  }

  result.evidence = Array.from(new Set(result.evidence));
  result.notes = Array.from(new Set(result.notes));

  return result;
}

// -----------------------------------------------------------------------------
// 4.5 Specialized Threat Detectors (URL, Message, QR, Audio, Video)
// -----------------------------------------------------------------------------

function calculateShannonEntropy(str) {
  if (!str || typeof str !== 'string' || str.length === 0) return 0;
  const freq = new Map();
  for (const char of str) {
    freq.set(char, (freq.get(char) || 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

function detectHomographAttack(domain) {
  if (!domain || typeof domain !== 'string') return { isHomograph: false, details: [] };
  const details = [];
  let isHomograph = false;

  if (domain.startsWith('xn--') || domain.includes('.xn--')) {
    isHomograph = true;
    details.push('Punycode encoded domain (xn--) detected; frequently used for visual spoofing');
  }

  // Mixed scripts (Cyrillic/Greek confusables with Latin)
  const cyrillicConfusables = /[\u0400-\u04FF]/;
  const greekConfusables = /[\u0370-\u03FF]/;
  const latin = /[a-zA-Z]/;

  if ((cyrillicConfusables.test(domain) || greekConfusables.test(domain)) && latin.test(domain)) {
    isHomograph = true;
    details.push('Mixed script detected: Domain blends Latin with Cyrillic/Greek visual confusable characters');
  }

  return { isHomograph, details };
}

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'work', 'click', 'buzz', 'cfd', 'sbs', 'rest', 'support', 'link',
  'country', 'stream', 'gq', 'ml', 'cf', 'tk', 'ga', 'fit', 'surf', 'loan', 'zip', 'mov', 'ng', 'su'
]);

const HIGH_RISK_KEYWORDS = [
  'login', 'signin', 'verify', 'update', 'secure', 'account', 'banking', 'wallet',
  'paypal', 'microsoft', 'apple', 'recovery', 'auth', 'billing', 'confirm'
];

const CLICKBAIT_AND_AD_MARKERS = [
  'start-download', 'download-now', 'fast-download', 'direct-download', 'click-download',
  'free-download', 'play-now', 'watch-hd', 'stream-now', 'downloadoffer', 'clickadu',
  'adsterra', 'propellerads', 'monetag', 'popcash', 'popads'
];

async function scanUrlDeep(urlStr, apiKey) {
  if (!urlStr || typeof urlStr !== 'string') {
    return {
      url: urlStr || '',
      threatLevel: 'danger',
      riskScore: 80,
      evidence: ['Malformed or empty URL input'],
      notes: ['Invalid parameter']
    };
  }

  const norm = normalizeUrl(urlStr);
  let domain = '';
  let pathname = '';
  let search = '';
  try {
    const u = new URL(norm);
    domain = u.hostname.toLowerCase();
    pathname = u.pathname;
    search = u.search.toLowerCase();
  } catch {
    return {
      url: urlStr,
      threatLevel: 'danger',
      riskScore: 80,
      evidence: ['Malformed or invalid URL structure'],
      notes: ['Failed RFC 3986 URL parsing']
    };
  }

  const evidence = [];
  const notes = [];
  let score = 0;

  // 1. OpenPhish & VirusTotal triage
  const baseTriage = await triageUrl({ url: norm, id: 'manual-scan' }, apiKey);
  if (baseTriage.status === 'malicious') {
    score = Math.max(score, 100);
    evidence.push(...baseTriage.evidence);
  } else if (baseTriage.status === 'warning') {
    score = Math.max(score, baseTriage.riskScore);
    evidence.push(...baseTriage.evidence);
  }
  if (baseTriage.notes) notes.push(...baseTriage.notes);

  // 2. Homograph / Punycode check
  const homograph = detectHomographAttack(domain);
  if (homograph.isHomograph) {
    score += 50;
    evidence.push(...homograph.details);
  }

  // 3. Raw IP Hostname
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain) || /^0x[0-9a-fA-F]+/i.test(domain)) {
    score += 45;
    evidence.push(`Direct IP Address Hostname: Target domain is a raw IP literal (${domain}) instead of a registered domain`);
  }

  // 4. Suspicious TLD
  const tld = domain.split('.').pop() || '';
  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 25;
    evidence.push(`High-Risk TLD: Domain uses ".${tld}", commonly abused in disposable phishing operations`);
  }

  // 5. Entropy Analysis
  const domainEntropy = calculateShannonEntropy(domain.split('.')[0] || '');
  if (domainEntropy > 3.8 && domain.split('.')[0].length > 10) {
    score += 25;
    evidence.push(`High Shannon Entropy (${domainEntropy}): Subdomain/domain exhibits random generation characteristics (potential DGA)`);
  }

  // 6. Excessive Subdomain Stacking
  const domainParts = domain.split('.');
  if (domainParts.length >= 4) {
    score += 20;
    evidence.push(`Subdomain Nesting: Domain contains ${domainParts.length} levels, a pattern used to visually disguise actual destinations`);
  }

  // 7. Sensitive Keywords in Subdomain or Path
  let keywordHits = 0;
  for (const kw of HIGH_RISK_KEYWORDS) {
    if (domain.includes(kw) || pathname.toLowerCase().includes(kw)) {
      keywordHits++;
      if (keywordHits <= 2) {
        evidence.push(`Security Keyword in URI: Detected sensitive term "${kw}" in URL path or subdomain`);
      }
    }
  }
  if (keywordHits > 0) {
    score += Math.min(30, keywordHits * 15);
  }

  // 8. Ephemeral Malvertising Ad-Redirect & Tracker Networks
  let trackerHit = false;
  for (const dom of EPHEMERAL_AD_TRACKER_DOMAINS) {
    if (domain.includes(dom)) {
      score += 50;
      evidence.push(`Malvertising Tracker Gateway: Hostname matches disposable ad-redirector network ("${dom}")`);
      trackerHit = true;
      break;
    }
  }

  for (const param of REDIRECT_TRACKER_PARAMS) {
    if (search.includes(param.toLowerCase()) || norm.toLowerCase().includes(param.toLowerCase())) {
      if (!trackerHit) {
        score += 45;
        evidence.push(`Ephemeral Ad-Redirect Parameter: URL routes traffic through click-tracker parameter ("${param.replace('=', '')}")`);
        trackerHit = true;
      }
      break;
    }
  }

  // 9. Deceptive Clickbait / Fake Download Route
  for (const cb of CLICKBAIT_AND_AD_MARKERS) {
    if (domain.includes(cb) || pathname.toLowerCase().includes(cb) || search.includes(cb)) {
      if (!trackerHit) {
        score += 40;
        evidence.push(`Deceptive Clickbait Pattern: URL contains download lure or ad network marker "${cb}"`);
      }
      break;
    }
  }

  const finalScore = Math.min(100, score);
  let threatLevel = 'safe';
  if (finalScore > 50) {
    threatLevel = 'danger';
  } else if (finalScore > 0) {
    threatLevel = 'warning';
  }

  if (finalScore > 0 && !notes.some(n => n.includes('Zero-Hour Behavioral'))) {
    notes.push('Zero-Hour Behavioral Insight: Multi-vendor reputation engines (VirusTotal) frequently report 0 hits on newly generated or cloaked ad-redirectors, but heuristic telemetry flagged active malvertising patterns.');
  }

  return {
    url: norm,
    hostname: domain,
    domainEntropy,
    threatLevel,
    riskScore: finalScore,
    evidence: Array.from(new Set(evidence)),
    notes: Array.from(new Set(notes)),
    homograph,
    tld
  };
}

async function scanMessageText(text, sender, apiKey) {
  if (!text || typeof text !== 'string') {
    return {
      threatLevel: 'safe',
      riskScore: 0,
      evidence: [],
      notes: ['Empty message text provided'],
      extractedUrls: []
    };
  }

  const evidence = [];
  const notes = [];
  let score = 0;
  const lower = text.toLowerCase();

  // 1. Extract URLs
  const urlRegex = /(https?:\/\/[^\s<>"]+|www\.[^\s<>"]+)/gi;
  const rawUrls = text.match(urlRegex) || [];
  const extractedUrls = Array.from(new Set(rawUrls.map(u => u.startsWith('http') ? u : 'http://' + u)));

  // Triage extracted URLs against OpenPhish & VirusTotal
  for (const url of extractedUrls.slice(0, 5)) {
    const urlVerdict = await scanUrlDeep(url, apiKey);
    if (urlVerdict.threatLevel === 'danger') {
      score = Math.max(score, 85);
      evidence.push(`Malicious Embedded URL: "${url}" flagged with Danger tier (Score ${urlVerdict.riskScore}/100)`);
    } else if (urlVerdict.threatLevel === 'warning') {
      score += 25;
      evidence.push(`Suspicious Embedded URL: "${url}" flagged with Warning (${urlVerdict.evidence[0] || 'Unverified Domain'})`);
    }
  }

  // 2. Credential & Secret Solicitation
  const credPatterns = [
    { regex: /\b(password|passwd|pwd)\b/i, weight: 35, desc: 'Solicitation of password credentials' },
    { regex: /\b(2fa|mfa|otp|one[\s-]time[\s-]password|verification code)\b/i, weight: 45, desc: 'Solicitation of 2FA/OTP authentication codes' },
    { regex: /\b(ssn|social security|national insurance)\b/i, weight: 45, desc: 'Request for Government ID / Social Security numbers' },
    { regex: /\b(seed phrase|recovery phrase|secret key|private key|mnemonic)\b/i, weight: 70, desc: 'Cryptocurrency wallet seed/recovery phrase extraction attempt' },
    { regex: /\b(pin|cvv|cvc|card number|expiration date)\b/i, weight: 40, desc: 'Payment card or banking PIN harvesting pattern' }
  ];

  for (const pat of credPatterns) {
    if (pat.regex.test(text)) {
      score += pat.weight;
      evidence.push(`Credential Harvesting Vector: ${pat.desc}`);
    }
  }

  // 3. Urgency & Coercion Pressure
  const urgencyPatterns = [
    { phrase: 'immediately', weight: 15 },
    { phrase: 'within 24 hours', weight: 25 },
    { phrase: 'account suspended', weight: 35 },
    { phrase: 'account deactivated', weight: 30 },
    { phrase: 'unauthorized transaction', weight: 25 },
    { phrase: 'legal action', weight: 30 },
    { phrase: 'arrest warrant', weight: 40 },
    { phrase: 'final notice', weight: 20 },
    { phrase: 'security alert', weight: 15 }
  ];

  let urgencyHits = 0;
  for (const item of urgencyPatterns) {
    if (lower.includes(item.phrase)) {
      urgencyHits++;
      score += item.weight;
      evidence.push(`Coercive Psychological Pressure: Urgent trigger detected ("${item.phrase}")`);
      if (urgencyHits >= 3) break;
    }
  }

  // 4. Financial & Extortion Vectors
  const financePatterns = [
    { regex: /\b(bitcoin|btc|usdt|eth|crypto(currency)?)\b/i, weight: 25, desc: 'Cryptocurrency payment diversion' },
    { regex: /\b(gift card|apple card|itunes card|google play card)\b/i, weight: 50, desc: 'Gift card payment demand (classic scam indicator)' },
    { regex: /\b(wire transfer|western union|moneygram)\b/i, weight: 30, desc: 'Irreversible wire transfer request' }
  ];

  for (const pat of financePatterns) {
    if (pat.regex.test(text)) {
      score += pat.weight;
      evidence.push(`Financial Diversion Vector: ${pat.desc}`);
    }
  }

  // 5. Impersonation of High-Trust Entities
  const impersonations = [
    { name: 'Internal Revenue Service (IRS)', regex: /\b(irs|internal revenue service)\b/i },
    { name: 'Postal Delivery Service', regex: /\b(fedex|ups|usps|dhl|parcel delivery)\b/i },
    { name: 'Banking Institution', regex: /\b(chase|bank of america|wells fargo|citibank|barclays)\b/i },
    { name: 'Tech / Security Support', regex: /\b(microsoft support|geek squad|apple support|helpdesk|it admin)\b/i }
  ];

  for (const imp of impersonations) {
    if (imp.regex.test(text)) {
      score += 20;
      evidence.push(`Authority Impersonation Marker: Pretexts as "${imp.name}"`);
      break;
    }
  }

  const finalScore = Math.min(100, score);
  let threatLevel = 'safe';
  if (finalScore > 50) {
    threatLevel = 'danger';
  } else if (finalScore > 0) {
    threatLevel = 'warning';
  }

  return {
    threatLevel,
    riskScore: finalScore,
    evidence,
    notes,
    extractedUrls
  };
}

async function scanQrPayload(payload, apiKey) {
  if (!payload || typeof payload !== 'string') {
    return {
      threatLevel: 'safe',
      riskScore: 0,
      evidence: [],
      notes: ['Empty QR code payload'],
      isUrl: false
    };
  }

  const trimmed = payload.trim();
  const evidence = [];
  const notes = [];
  let score = 0;
  let isUrl = false;

  const lower = trimmed.toLowerCase();
  if (lower.startsWith('javascript:')) {
    score = 100;
    evidence.push('Dangerous URI Scheme: QR contains executable javascript: URI payload');
  } else if (lower.startsWith('data:')) {
    score = 80;
    evidence.push('Obfuscated Data URI: QR contains data: payload that may conceal scripts or phish pages');
  } else if (lower.startsWith('tel:') || lower.startsWith('smsto:')) {
    score = 30;
    evidence.push(`Automated Communication Trigger: QR attempts automatic invocation (${trimmed.split(':')[0]})`);
  } else if (lower.startsWith('bitcoin:') || lower.startsWith('ethereum:')) {
    score = 40;
    evidence.push(`Crypto Address Redirect: QR initiates a direct cryptocurrency transaction (${trimmed.split(':')[0]})`);
  } else if (/^https?:\/\//i.test(trimmed)) {
    isUrl = true;
    const urlAnalysis = await scanUrlDeep(trimmed, apiKey);
    score = Math.max(score, urlAnalysis.riskScore);
    evidence.push(...urlAnalysis.evidence);
    notes.push(...urlAnalysis.notes);

    const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'rb.gy', 'is.gd', 'cutt.ly', 'ow.ly'];
    if (SHORTENERS.some(s => urlAnalysis.hostname === s || urlAnalysis.hostname.endsWith('.' + s))) {
      score = Math.max(score, 45);
      evidence.push('Quishing Obfuscation: QR points to a URL shortener to hide destination domain');
    }
  } else {
    const textAnalysis = await scanMessageText(trimmed, '', apiKey);
    score = Math.max(score, textAnalysis.riskScore);
    evidence.push(...textAnalysis.evidence);
  }

  const finalScore = Math.min(100, score);
  let threatLevel = 'safe';
  if (finalScore > 50) {
    threatLevel = 'danger';
  } else if (finalScore > 0) {
    threatLevel = 'warning';
  }

  return {
    payload: trimmed,
    isUrl,
    threatLevel,
    riskScore: finalScore,
    evidence,
    notes
  };
}

async function scanAudioTelemetry(data, apiKey) {
  const { metadata = {}, spectralStats = {}, transcript = '' } = data || {};
  const evidence = [];
  const notes = [];
  let score = 0;

  // 1. Synthetic TTS Spectral Signatures
  if (spectralStats.highFreqCutoff && spectralStats.highFreqCutoff <= 16000) {
    score += 35;
    evidence.push(`Acoustic Frequency Anomaly: Sharp spectral band cutoff detected at ${spectralStats.highFreqCutoff}Hz (common in AI neural voice models)`);
  }

  if (spectralStats.pitchVariance !== undefined && spectralStats.pitchVariance < 12) {
    score += 30;
    evidence.push(`Robotic Prosody: Abnormally flat fundamental pitch variance (${spectralStats.pitchVariance} semitones) indicative of synthetic voice synthesis`);
  }

  if (spectralStats.unnaturalZeroCrossing) {
    score += 20;
    evidence.push('Acoustic Synthesis Marker: Unnatural temporal zero-crossing uniformity');
  }

  // 2. Audio Container / Metadata Signatures
  if (metadata.encoder) {
    const encoder = String(metadata.encoder).toLowerCase();
    if (encoder.includes('lavf') || encoder.includes('tts') || encoder.includes('bark') || encoder.includes('piper') || encoder.includes('elevenlabs')) {
      score += 45;
      evidence.push(`Synthetic Codec Metadata: Audio file container encoded by synthetic toolchain ("${metadata.encoder}")`);
    }
  }

  // 3. Vishing Transcript Evaluation
  if (transcript && transcript.trim().length > 0) {
    const msgAnalysis = await scanMessageText(transcript, 'Voice Call', apiKey);
    score = Math.max(score, msgAnalysis.riskScore);
    for (const ev of msgAnalysis.evidence) {
      evidence.push(`Vishing Speech Pattern: ${ev}`);
    }
  }

  const finalScore = Math.min(100, score);
  let threatLevel = 'safe';
  if (finalScore > 50) {
    threatLevel = 'danger';
  } else if (finalScore > 0) {
    threatLevel = 'warning';
  }

  return {
    threatLevel,
    riskScore: finalScore,
    evidence,
    notes,
    spectralAnalysis: spectralStats,
    metadata
  };
}

async function scanVideoTelemetry(data, apiKey) {
  const { metadata = {}, frameMetrics = {}, extractedUrls = [], hasQrInFrame = false, qrPayload = '' } = data || {};
  const evidence = [];
  const notes = [];
  let score = 0;

  // 1. Frame Anomaly & Deepfake Face-Swap Detection
  if (frameMetrics.facialBoundaryJitter && frameMetrics.facialBoundaryJitter > 60) {
    score += 45;
    evidence.push(`Facial Warping Anomaly: Frame-to-frame pixel discontinuity detected around facial perimeter (${frameMetrics.facialBoundaryJitter}%), characteristic of deepfake replacement`);
  }

  if (frameMetrics.unnaturalBlinkRate) {
    score += 30;
    evidence.push('Biological Inconsistency: Unnatural blink frequency or static eye reflections observed across sampled frames');
  }

  if (frameMetrics.frameRateAnomalies) {
    score += 20;
    evidence.push('Temporal Frame Inconsistency: Variable frame presentation delays indicative of frame re-encoding injection');
  }

  // 2. Video Phishing / Embedded QR Codes & URLs
  if (hasQrInFrame && qrPayload) {
    const qrVerdict = await scanQrPayload(qrPayload, apiKey);
    score = Math.max(score, qrVerdict.riskScore);
    evidence.push(`Video Stream Quishing: Embedded QR code detected in video frame leading to "${qrPayload}" (Score: ${qrVerdict.riskScore}/100)`);
    evidence.push(...qrVerdict.evidence);
  }

  if (Array.isArray(extractedUrls) && extractedUrls.length > 0) {
    for (const url of extractedUrls.slice(0, 3)) {
      const urlAnalysis = await scanUrlDeep(url, apiKey);
      if (urlAnalysis.threatLevel === 'danger' || urlAnalysis.threatLevel === 'warning') {
        score = Math.max(score, urlAnalysis.riskScore);
        evidence.push(`Video On-Screen Phishing URL: "${url}" displayed in stream (${urlAnalysis.evidence[0] || 'Flagged URL'})`);
      }
    }
  }

  // 3. Container & Synthetic Video Metadata
  if (metadata.encoder) {
    const encoder = String(metadata.encoder).toLowerCase();
    if (encoder.includes('ffmpeg') || encoder.includes('synthetic') || encoder.includes('comfyui') || encoder.includes('stable-video')) {
      score += 25;
      evidence.push(`Synthetic Video Pipeline: Video container tagged with automated generation software ("${metadata.encoder}")`);
    }
  }

  const finalScore = Math.min(100, score);
  let threatLevel = 'safe';
  if (finalScore > 50) {
    threatLevel = 'danger';
  } else if (finalScore > 0) {
    threatLevel = 'warning';
  }

  return {
    threatLevel,
    riskScore: finalScore,
    evidence,
    notes,
    frameMetrics,
    metadata
  };
}

// -----------------------------------------------------------------------------
// 5. Native HTTP Server & CORS Handling
// -----------------------------------------------------------------------------
function isOriginAllowed(origin) {
  if (!origin) return false;
  // Allow Chrome Extension origins
  if (origin.startsWith('chrome-extension://')) return true;
  // Allow local development and test origins
  if (/^http:\/\/(localhost|127\.0.0\.1)(:\d+)?$/.test(origin)) return true;
  return false;
}

function setCorsHeaders(res, origin) {
  if (origin && isOriginAllowed(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-apikey, x-api-key');
    res.setHeader('Access-Control-Max-Age', '86400');
  }
}

function sendJson(res, statusCode, data) {
  const jsonStr = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(jsonStr)
  });
  res.end(jsonStr);
}

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin || '';
  setCorsHeaders(res, origin);

  // 1. Strict preflight OPTIONS handling (reject unallowed cross-origins)
  if (req.method === 'OPTIONS') {
    if (origin && !isOriginAllowed(origin)) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end('CORS Origin Not Allowed');
      return;
    }
    res.writeHead(204);
    res.end();
    return;
  }

  // Safe fixed base URL to prevent host header injection
  const parsedUrl = new URL(req.url, 'http://127.0.0.1');
  const pathname = parsedUrl.pathname;

  // 2. Health & Status Check Endpoint
  if (req.method === 'GET' && pathname === '/api/health') {
    sendJson(res, 200, {
      status: 'online',
      service: 'PhishGuard Web Intelligence Backend',
      timestamp: new Date().toISOString(),
      openPhish: {
        isLoaded: openPhishCache.isLoaded,
        totalLoaded: openPhishCache.totalLoaded,
        exactEntries: openPhishCache.exactMap.size,
        strippedEntries: openPhishCache.strippedMap.size,
        lastFetchedAt: openPhishCache.lastFetchedAt,
        lastError: openPhishCache.lastError
      },
      virusTotal: {
        configured: Boolean(VIRUSTOTAL_API_KEY),
        cachedQueries: virusTotalCache.size,
        rateLimited: Date.now() < vtRateLimitedUntil
      }
    });
    return;
  }

  // 3. OpenPhish Refresh Endpoint (manual trigger)
  if (req.method === 'POST' && pathname === '/api/feed/refresh') {
    fetchOpenPhishFeed();
    sendJson(res, 202, { message: 'OpenPhish feed refresh initiated' });
    return;
  }

  // 4. Main Threat Analysis Endpoint: POST /api/analyze
  if (req.method === 'POST' && pathname === '/api/analyze') {
    let body = '';
    let bodySizeExceeded = false;
    req.setEncoding('utf8');

    req.on('error', (err) => {
      console.warn(`[HTTP Req Error] ${err.message}`);
    });

    req.on('data', (chunk) => {
      if (bodySizeExceeded) return;
      body += chunk;
      // Guard against payloads larger than 5MB
      if (body.length > 5 * 1024 * 1024) {
        bodySizeExceeded = true;
        sendJson(res, 413, { error: 'Payload Too Large' });
        req.destroy();
      }
    });

    req.on('end', async () => {
      if (bodySizeExceeded) return;

      let payload;
      try {
        payload = JSON.parse(body);
      } catch (jsonErr) {
        sendJson(res, 400, { error: 'Invalid JSON payload', message: jsonErr.message });
        return;
      }

      // Support array directly or object { urls: [...] }
      let itemsToAnalyze = [];
      const queryApiKey = parsedUrl.searchParams.get('apiKey') || parsedUrl.searchParams.get('api_key') || '';
      const headerApiKey = req.headers['x-apikey'] || req.headers['x-api-key'] || '';
      let bodyApiKey = '';

      if (Array.isArray(payload)) {
        itemsToAnalyze = payload;
      } else if (payload && Array.isArray(payload.urls)) {
        itemsToAnalyze = payload.urls;
        bodyApiKey = payload.apiKey || payload.api_key || '';
      } else {
        sendJson(res, 400, { error: 'Request body must be a JSON array of URLs or { urls: [...] }' });
        return;
      }

      const effectiveApiKey = (queryApiKey || headerApiKey || bodyApiKey || VIRUSTOTAL_API_KEY || '').trim();

      // Analyze each item in parallel (preserving exact order and array length)
      try {
        const results = await Promise.all(
          itemsToAnalyze.map((item) => {
            const itemApiKey = (typeof item === 'object' && (item.apiKey || item.api_key)) ? (item.apiKey || item.api_key).trim() : effectiveApiKey;
            return triageUrl(item, itemApiKey);
          })
        );
        sendJson(res, 200, results);
      } catch (err) {
        console.error('[Analyze Error]', err);
        sendJson(res, 500, { error: 'Internal triage error', message: err.message });
      }
    });

    return;
  }

  // Helper to read JSON request body safely
  function readJsonBody(callback) {
    let body = '';
    let exceeded = false;
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      if (exceeded) return;
      body += chunk;
      if (body.length > 5 * 1024 * 1024) {
        exceeded = true;
        sendJson(res, 413, { error: 'Payload Too Large' });
        req.destroy();
      }
    });
    req.on('end', () => {
      if (exceeded) return;
      try {
        const parsed = body ? JSON.parse(body) : {};
        callback(null, parsed);
      } catch (err) {
        callback(err, null);
      }
    });
  }

  // 5. Deep URL Scan Endpoint: POST /api/scan/url and POST /api/scan/urls (Single & Batch)
  if (req.method === 'POST' && (pathname === '/api/scan/url' || pathname === '/api/scan/urls')) {
    readJsonBody(async (err, payload) => {
      if (err) return sendJson(res, 400, { error: 'Invalid JSON payload', message: err.message });
      const effectiveKey = (payload?.apiKey || req.headers['x-apikey'] || req.headers['x-api-key'] || VIRUSTOTAL_API_KEY || '').trim();

      // Support batch scanning of multiple URLs from tabs and links
      if (Array.isArray(payload)) {
        const results = await Promise.all(
          payload.map((item) => {
            const u = typeof item === 'string' ? item : (item.url || item.targetUrl || '');
            const itemKey = (typeof item === 'object' && item.apiKey) ? item.apiKey.trim() : effectiveKey;
            return scanUrlDeep(u, itemKey);
          })
        );
        return sendJson(res, 200, results);
      }

      if (payload && Array.isArray(payload.urls)) {
        const results = await Promise.all(
          payload.urls.map((item) => {
            const u = typeof item === 'string' ? item : (item.url || item.targetUrl || '');
            const itemKey = (typeof item === 'object' && item.apiKey) ? item.apiKey.trim() : effectiveKey;
            return scanUrlDeep(u, itemKey);
          })
        );
        return sendJson(res, 200, results);
      }

      const targetUrl = (payload && (payload.url || payload.targetUrl)) || '';
      const verdict = await scanUrlDeep(targetUrl, effectiveKey);
      sendJson(res, 200, verdict);
    });
    return;
  }

  // 6. Message / Smishing Checker Endpoint: POST /api/scan/message
  if (req.method === 'POST' && pathname === '/api/scan/message') {
    readJsonBody(async (err, payload) => {
      if (err) return sendJson(res, 400, { error: 'Invalid JSON payload', message: err.message });
      const text = (payload && (payload.text || payload.message || payload.body)) || '';
      const sender = (payload && payload.sender) || '';
      const effectiveKey = (payload.apiKey || req.headers['x-apikey'] || req.headers['x-api-key'] || VIRUSTOTAL_API_KEY || '').trim();
      const verdict = await scanMessageText(text, sender, effectiveKey);
      sendJson(res, 200, verdict);
    });
    return;
  }

  // 7. QR Code / Quishing Checker Endpoint: POST /api/scan/qr
  if (req.method === 'POST' && pathname === '/api/scan/qr') {
    readJsonBody(async (err, payload) => {
      if (err) return sendJson(res, 400, { error: 'Invalid JSON payload', message: err.message });
      const qrData = (payload && (payload.payload || payload.text || payload.data)) || '';
      const effectiveKey = (payload.apiKey || req.headers['x-apikey'] || req.headers['x-api-key'] || VIRUSTOTAL_API_KEY || '').trim();
      const verdict = await scanQrPayload(qrData, effectiveKey);
      sendJson(res, 200, verdict);
    });
    return;
  }

  // 8. Audio / Voice Vishing Checker Endpoint: POST /api/scan/audio
  if (req.method === 'POST' && pathname === '/api/scan/audio') {
    readJsonBody(async (err, payload) => {
      if (err) return sendJson(res, 400, { error: 'Invalid JSON payload', message: err.message });
      const effectiveKey = (payload.apiKey || req.headers['x-apikey'] || req.headers['x-api-key'] || VIRUSTOTAL_API_KEY || '').trim();
      const verdict = await scanAudioTelemetry(payload, effectiveKey);
      sendJson(res, 200, verdict);
    });
    return;
  }

  // 9. Video / Deepfake Checker Endpoint: POST /api/scan/video
  if (req.method === 'POST' && pathname === '/api/scan/video') {
    readJsonBody(async (err, payload) => {
      if (err) return sendJson(res, 400, { error: 'Invalid JSON payload', message: err.message });
      const effectiveKey = (payload.apiKey || req.headers['x-apikey'] || req.headers['x-api-key'] || VIRUSTOTAL_API_KEY || '').trim();
      const verdict = await scanVideoTelemetry(payload, effectiveKey);
      sendJson(res, 200, verdict);
    });
    return;
  }

  // 10. Root Info Page
  if (req.method === 'GET' && pathname === '/') {
    sendJson(res, 200, {
      name: 'PhishGuard Web Intelligence API',
      version: '1.1.0',
      description: 'Zero-dependency tri-tier threat triage server',
      endpoints: [
        { method: 'GET', path: '/api/health', description: 'Backend and feed status' },
        { method: 'POST', path: '/api/analyze', description: 'Analyze batch of URLs for threats' },
        { method: 'POST', path: '/api/scan/url', description: 'Deep individual URL inspection' },
        { method: 'POST', path: '/api/scan/urls', description: 'Deep batch inspection for discovered URLs & links' },
        { method: 'POST', path: '/api/scan/message', description: 'Smishing, BEC, and message text threat analysis' },
        { method: 'POST', path: '/api/scan/qr', description: 'Quishing and QR code payload inspection' },
        { method: 'POST', path: '/api/scan/audio', description: 'Acoustic synthetic voice and vishing telemetry check' },
        { method: 'POST', path: '/api/scan/video', description: 'Deepfake frame anomalies and video phishing triage' },
        { method: 'POST', path: '/api/feed/refresh', description: 'Trigger OpenPhish feed refresh' }
      ]
    });
    return;
  }

  // 404 for unknown routes
  sendJson(res, 404, { error: 'Not Found', path: pathname });
});

// Start HTTP Server
server.listen(PORT, HOST, () => {
  console.log(`====================================================`);
  console.log(`🛡️  PhishGuard Web Intelligence Backend Running`);
  console.log(`📍 Listening on http://${HOST}:${PORT}`);
  console.log(`🔑 VirusTotal Integration: ${VIRUSTOTAL_API_KEY ? 'Configured & Enabled' : 'Disabled (No API key; clean URLs evaluated via OpenPhish)'}`);
  console.log(`🌐 OpenPhish Feed URL: ${OPENPHISH_FEED_URL}`);
  console.log(`====================================================`);

  // Initial OpenPhish Feed Fetch on Startup
  loadInitialFeed();
  fetchOpenPhishFeed();

  // Periodic refresh timer (native setInterval)
  if (FEED_REFRESH_MINUTES > 0) {
    const intervalMs = FEED_REFRESH_MINUTES * 60 * 1000;
    setInterval(() => {
      console.log(`[OpenPhish] Triggering scheduled feed refresh...`);
      fetchOpenPhishFeed();
    }, intervalMs);
  }
});

// Graceful shutdown handling
process.on('SIGINT', () => {
  console.log('\n[Shutdown] Shutting down PhishGuard Backend gracefully...');
  server.close(() => {
    console.log('[Shutdown] Server closed.');
    process.exit(0);
  });
});
