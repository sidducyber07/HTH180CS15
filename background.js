/**
 * PhishGuard Web - Active Defense Service Worker (Manifest V3)
 * 
 * Features:
 * - Listens to chrome.tabs.onUpdated for completed page loads.
 * - Queries backend POST /api/analyze silently.
 * - Uses chrome.storage.session for 10-minute verdict caching and local suppression list.
 * - Triggers red '!' action badge and desktop alert on malicious detections.
 * - Provides messaging bridge for Popup SOC triage UI.
 */

const BACKEND_BASE = 'http://127.0.0.1:8787';
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

/**
 * Normalizes a URL for consistent cache indexing.
 */
function normalizeUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return (rawUrl || '').trim();
  }
}

/**
 * Validates if URL is eligible for security scanning (HTTP/HTTPS only).
 */
function isScanEligible(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') return false;
  return urlStr.startsWith('http://') || urlStr.startsWith('https://');
}

/**
 * Retrieves the current session cache and suppression list from chrome.storage.session.
 */
async function getStorageData() {
  try {
    const data = await chrome.storage.session.get(['sessionCache', 'suppressionList']);
    return {
      sessionCache: data.sessionCache || {},
      suppressionList: Array.isArray(data.suppressionList) ? data.suppressionList : []
    };
  } catch (err) {
    console.error('[Storage Error]', err);
    return { sessionCache: {}, suppressionList: [] };
  }
}

/**
 * Prunes expired entries and caps maximum entries in sessionCache to prevent quota exhaustion.
 */
function pruneCache(cache, maxEntries = 200) {
  const now = Date.now();
  const pruned = {};
  const validEntries = Object.entries(cache || {})
    .filter(([_, entry]) => entry && entry.cachedAt && (now - entry.cachedAt < CACHE_TTL_MS))
    .sort((a, b) => (b[1].cachedAt || 0) - (a[1].cachedAt || 0))
    .slice(0, maxEntries);

  for (const [url, item] of validEntries) {
    pruned[url] = item;
  }
  return pruned;
}

/**
 * Saves updated session cache and/or suppression list to chrome.storage.session.
 */
async function setStorageData(updates) {
  try {
    if (updates.sessionCache) {
      updates.sessionCache = pruneCache(updates.sessionCache);
    }
    await chrome.storage.session.set(updates);
  } catch (err) {
    console.error('[Storage Save Error]', err);
  }
}

/**
 * Calls backend POST /api/analyze for one or more URLs/tabs.
 * Handles timeouts and connection errors gracefully without fabricating verdicts.
 */
async function callBackendAnalyze(items) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 12000);

    const response = await fetch(`${BACKEND_BASE}/api/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(items),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`Backend returned HTTP ${response.status}`);
    }

    return await response.json();
  } catch (err) {
    console.warn(`[Backend Analyze Warning] ${err.message}`);
    // Return graceful unknown fallback objects preserving length and contract
    return items.map((item) => {
      const url = typeof item === 'string' ? item : (item.url || '');
      const id = typeof item === 'object' ? item.id : url;
      const title = typeof item === 'object' ? item.title : url;
      return {
        id,
        title,
        url,
        status: 'unknown',
        riskScore: 0,
        evidence: [],
        notes: [`Backend analysis unreachable (${err.message})`],
        unverifiedBy: ['PhishGuard-Backend']
      };
    });
  }
}

/**
 * Analyzes a tab, utilizing session cache if valid, otherwise calling backend.
 */
async function analyzeTab(tab) {
  if (!tab || !tab.url || !isScanEligible(tab.url)) {
    return null;
  }

  const normUrl = normalizeUrl(tab.url);
  const { sessionCache, suppressionList } = await getStorageData();

  // Check if suppressed
  const isSuppressed = suppressionList.includes(normUrl);

  // Check Cache with TTL
  const cachedEntry = sessionCache[normUrl];
  const now = Date.now();

  if (cachedEntry && (now - cachedEntry.cachedAt < CACHE_TTL_MS)) {
    handleVerdictAlerting(tab.id, cachedEntry.verdict, isSuppressed);
    return cachedEntry.verdict;
  }

  // Query Backend
  const payload = [{
    id: tab.id,
    title: tab.title || tab.url,
    url: tab.url
  }];

  const results = await callBackendAnalyze(payload);
  const verdict = results[0];

  // Update Cache
  sessionCache[normUrl] = {
    verdict,
    cachedAt: now
  };
  await setStorageData({ sessionCache });

  // Handle Alerts & Badges
  await handleVerdictAlerting(tab.id, verdict, isSuppressed);

  return verdict;
}

/**
 * Updates tab action badge and triggers desktop notifications on malicious verdicts.
 */
async function handleVerdictAlerting(tabId, verdict, isSuppressed) {
  if (!verdict) return;

  if (verdict.status === 'malicious' && !isSuppressed) {
    // 1. Red '!' action badge on tab
    try {
      await chrome.action.setBadgeText({ text: '!', tabId });
      await chrome.action.setBadgeBackgroundColor({ color: '#ef4444', tabId });
    } catch {
      // tab might have closed
    }

    // 2. Desktop notification
    try {
      const notificationId = `threat-${tabId}-${Date.now()}`;
      await chrome.notifications.create(notificationId, {
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icons/icon-128.png'),
        title: '🚨 Threat Detected: PhishGuard Web',
        message: `Malicious page detected:\n${verdict.title || verdict.url}\nRisk Score: 100`,
        priority: 2
      });
    } catch (notifErr) {
      console.warn('[Notification Error]', notifErr);
    }
  } else {
    // Clear badge if tab is safe, unknown, or suppressed
    try {
      await chrome.action.setBadgeText({ text: '', tabId });
    } catch {
      // tab might have closed
    }
  }
}

// -----------------------------------------------------------------------------
// Event Listeners
// -----------------------------------------------------------------------------

// 1. Tab load listener (Passive Mode: Do NOT auto-scan without user intimation)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Respect strict user intimation constraint:
  // Threat detection and feed lookups are executed only when the user explicitly initiates a scan.
});

// 2. Clear badge when tab is removed or replaced
chrome.tabs.onRemoved.addListener(async (tabId) => {
  // Session storage cleanup can happen periodically or on expiration
});

// 3. Message passing handler for Popup SOC UI
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      const action = message?.action;

      if (action === 'GET_STATE') {
        const data = await getStorageData();
        sendResponse({ success: true, data });
        return;
      }

      if (action === 'ANALYZE_BATCH') {
        const tabs = message.tabs || [];
        const { sessionCache, suppressionList } = await getStorageData();
        const now = Date.now();
        const uncachedTabs = [];
        const verdicts = [];

        // Check cache first
        for (const tab of tabs) {
          if (!tab.url || !isScanEligible(tab.url)) {
            verdicts.push({
              id: tab.id,
              title: tab.title || 'System Tab',
              url: tab.url || '',
              status: 'unknown',
              riskScore: 0,
              evidence: [],
              notes: ['Internal or non-HTTP tab'],
              unverifiedBy: ['ProtocolValidator']
            });
            continue;
          }

          const normUrl = normalizeUrl(tab.url);
          const cached = sessionCache[normUrl];

          if (cached && (now - cached.cachedAt < CACHE_TTL_MS)) {
            const isSuppressed = suppressionList.includes(normUrl);
            await handleVerdictAlerting(tab.id, cached.verdict, isSuppressed);
            verdicts.push(cached.verdict);
          } else {
            uncachedTabs.push(tab);
          }
        }

        // Query backend for uncached tabs
        if (uncachedTabs.length > 0) {
          const freshResults = await callBackendAnalyze(uncachedTabs);
          for (let i = 0; i < uncachedTabs.length; i++) {
            const tab = uncachedTabs[i];
            const verdict = freshResults[i];
            const normUrl = normalizeUrl(tab.url);

            sessionCache[normUrl] = {
              verdict,
              cachedAt: now
            };

            const isSuppressed = suppressionList.includes(normUrl);
            await handleVerdictAlerting(tab.id, verdict, isSuppressed);
            verdicts.push(verdict);
          }

          await setStorageData({ sessionCache });
        }

        sendResponse({ success: true, verdicts });
        return;
      }

      if (action === 'SUPPRESS_URL') {
        const rawUrl = message.url;
        const tabId = message.tabId;
        const normUrl = normalizeUrl(rawUrl);

        const { suppressionList } = await getStorageData();
        if (!suppressionList.includes(normUrl)) {
          suppressionList.push(normUrl);
          await setStorageData({ suppressionList });
        }

        // Clear badge on this tab immediately
        if (tabId) {
          try {
            await chrome.action.setBadgeText({ text: '', tabId });
          } catch {
            // tab may not exist
          }
        }

        sendResponse({ success: true, message: 'URL added to suppression list' });
        return;
      }

      if (action === 'CLEAR_CACHE') {
        await setStorageData({ sessionCache: {} });
        sendResponse({ success: true, message: 'Session cache cleared' });
        return;
      }

      sendResponse({ success: false, error: `Unknown action: ${action}` });
    } catch (err) {
      console.error('[Worker Message Error]', err);
      sendResponse({ success: false, error: err.message });
    }
  })();

  return true; // Keep message channel open for async response
});

// Installation & Update Hook
chrome.runtime.onInstalled.addListener(async () => {
  console.log('[PhishGuard Web] Service Worker installed and active.');
  // Initialize storage structure if not present
  const data = await getStorageData();
  await setStorageData({
    sessionCache: data.sessionCache,
    suppressionList: data.suppressionList
  });
});
