/**
 * PhishGuard Web - SOC Triage Popup Logic
 * Vanilla JavaScript (No Frameworks)
 * 
 * Features:
 * - Tab query & merge with active background.js session cache.
 * - Tri-state dynamic accordion rendering (Malicious, Unknown, Safe).
 * - Remediation Hook: Close Tab (chrome.tabs.remove + DOM removal).
 * - Remediation Hook: Report False Positive (navigator.clipboard.writeText + suppression).
 * - Real-time metrics counters, filtering, and Rescan Open Tabs trigger.
 */

const BACKEND_HEALTH_URL = 'http://127.0.0.1:8787/api/health';

// Local UI state
const state = {
  tabs: [],            // Chrome tab objects
  triageData: new Map(), // tabId -> verdict object
  suppressionList: [], // array of suppressed URLs
  currentFilter: 'all',// 'all' | 'malicious' | 'unknown' | 'safe'
  isScanning: false
};

// DOM Elements
const elList = document.getElementById('accordion-list');
const elEmpty = document.getElementById('empty-state');
const elLoading = document.getElementById('loading-indicator');
const elBtnRescan = document.getElementById('btn-rescan');
const elToast = document.getElementById('toast-banner');
const elToastText = document.getElementById('toast-text');
const elStatusPill = document.getElementById('backend-status-pill');
const elCountMalicious = document.getElementById('count-malicious');
const elCountUnknown = document.getElementById('count-unknown');
const elCountSafe = document.getElementById('count-safe');
const elCountTotal = document.getElementById('count-total');
const filterButtons = document.querySelectorAll('.filter-btn');

/**
 * Escapes HTML characters to prevent XSS.
 */
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Extracts a clean hostname or fallback string.
 */
function getHostname(urlStr) {
  try {
    return new URL(urlStr).hostname;
  } catch {
    return urlStr || 'about:blank';
  }
}

/**
 * Displays a transient notification toast banner.
 */
let toastTimeout = null;
function showToast(message) {
  elToastText.textContent = message;
  elToast.classList.remove('hidden');
  if (toastTimeout) clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => {
    elToast.classList.add('hidden');
  }, 3500);
}

/**
 * Checks connection health to Node.js backend.
 */
async function checkBackendHealth() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1500);

    const res = await fetch(BACKEND_HEALTH_URL, {
      method: 'GET',
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      elStatusPill.className = 'status-pill';
      elStatusPill.innerHTML = '<span class="status-dot"></span><span class="status-text">API Online</span>';
      elStatusPill.title = 'Connected to 127.0.0.1:8787';
      return true;
    }
  } catch {
    // API offline or unreachable
  }

  elStatusPill.className = 'status-pill status-offline';
  elStatusPill.innerHTML = '<span class="status-dot"></span><span class="status-text">API Offline</span>';
  elStatusPill.title = 'Cannot reach http://127.0.0.1:8787. Ensure server.js is running.';
  return false;
}

/**
 * Fetches open tabs, merges with background session cache, queries uncached.
 */
async function loadAndTriageTabs(forceRescan = false) {
  if (state.isScanning) return;
  state.isScanning = true;

  elBtnRescan.classList.add('is-scanning');
  elLoading.classList.remove('hidden');
  elEmpty.classList.add('hidden');

  try {
    // 1. Fetch current open tabs
    const allTabs = await chrome.tabs.query({});
    
    // Filter to inspectable HTTP/HTTPS tabs
    const inspectableTabs = allTabs.filter(tab => {
      const url = tab.url || '';
      return url.startsWith('http://') || url.startsWith('https://');
    });

    state.tabs = inspectableTabs;

    // 2. Fetch active session cache and suppression list from service worker
    const backgroundState = await chrome.runtime.sendMessage({ action: 'GET_STATE' });
    const sessionCache = backgroundState?.data?.sessionCache || {};
    state.suppressionList = backgroundState?.data?.suppressionList || [];

    const now = Date.now();
    const CACHE_TTL_MS = 10 * 60 * 1000;
    const uncachedTabs = [];
    const resolvedVerdicts = new Map();

    // 3. Match against session cache
    for (const tab of inspectableTabs) {
      const rawUrl = tab.url || '';
      const normUrl = rawUrl.split('#')[0]; // simple normalize
      const cached = sessionCache[normUrl];

      if (!forceRescan && cached && (now - cached.cachedAt < CACHE_TTL_MS)) {
        resolvedVerdicts.set(tab.id, cached.verdict);
      } else {
        uncachedTabs.push(tab);
      }
    }

    // 4. Request fresh analysis for uncached tabs
    if (uncachedTabs.length > 0) {
      const analyzeResponse = await chrome.runtime.sendMessage({
        action: 'ANALYZE_BATCH',
        tabs: uncachedTabs.map(t => ({ id: t.id, title: t.title, url: t.url }))
      });

      if (analyzeResponse?.success && Array.isArray(analyzeResponse.verdicts)) {
        for (let i = 0; i < uncachedTabs.length; i++) {
          const tab = uncachedTabs[i];
          const verdict = analyzeResponse.verdicts[i];
          if (verdict) {
            resolvedVerdicts.set(tab.id, verdict);
          }
        }
      }
    }

    state.triageData = resolvedVerdicts;

    // 5. Update UI
    renderAccordionList();
    updateMetrics();

  } catch (err) {
    console.error('[Popup Triage Error]', err);
    showToast(`Error during triage: ${err.message}`);
  } finally {
    state.isScanning = false;
    elBtnRescan.classList.remove('is-scanning');
    elLoading.classList.add('hidden');
  }
}

/**
 * Updates summary metrics ribbon.
 */
function updateMetrics() {
  let malicious = 0;
  let unknown = 0;
  let safe = 0;

  for (const tab of state.tabs) {
    const verdict = state.triageData.get(tab.id);
    if (!verdict) continue;

    const normUrl = (tab.url || '').split('#')[0];
    const isSuppressed = state.suppressionList.includes(normUrl);

    if (verdict.status === 'malicious') {
      if (isSuppressed) {
        // Count suppressed threats separately or under safe/suppressed
        safe++;
      } else {
        malicious++;
      }
    } else if (verdict.status === 'safe') {
      safe++;
    } else {
      unknown++;
    }
  }

  elCountMalicious.textContent = malicious;
  elCountUnknown.textContent = unknown;
  elCountSafe.textContent = safe;
  elCountTotal.textContent = state.tabs.length;
}

/**
 * Renders the accordion list according to Tri-State specifications:
 * - Malicious tabs: Red border, expanded by default, riskScore: 100, bulleted evidence list.
 * - Unknown tabs: Gray border, list missing sources in unverifiedBy array.
 * - Safe tabs: Subtle border, collapsed by default.
 */
function renderAccordionList() {
  elList.innerHTML = '';

  if (state.tabs.length === 0) {
    elEmpty.classList.remove('hidden');
    return;
  }

  elEmpty.classList.add('hidden');

  let visibleCount = 0;

  for (const tab of state.tabs) {
    const verdict = state.triageData.get(tab.id) || {
      id: tab.id,
      title: tab.title,
      url: tab.url,
      status: 'unknown',
      riskScore: 0,
      evidence: [],
      notes: ['Pending analysis'],
      unverifiedBy: ['Pending']
    };

    const normUrl = (tab.url || '').split('#')[0];
    const isSuppressed = state.suppressionList.includes(normUrl);

    // Apply Filter
    if (state.currentFilter === 'malicious' && (verdict.status !== 'malicious' || isSuppressed)) {
      continue;
    }
    if (state.currentFilter === 'unknown' && verdict.status !== 'unknown') {
      continue;
    }
    if (state.currentFilter === 'safe' && verdict.status !== 'safe' && !isSuppressed) {
      continue;
    }

    visibleCount++;

    const isMalicious = verdict.status === 'malicious' && !isSuppressed;
    const isUnknown = verdict.status === 'unknown';
    const isSafe = verdict.status === 'safe';

    // Item element
    const itemEl = document.createElement('div');
    itemEl.className = 'accordion-item';
    itemEl.dataset.tabId = tab.id;

    if (isMalicious) {
      itemEl.classList.add('is-malicious', 'is-open'); // Red border, expanded by default
    } else if (isSuppressed) {
      itemEl.classList.add('is-suppressed');
    } else if (isUnknown) {
      itemEl.classList.add('is-unknown'); // Gray border
    } else if (isSafe) {
      itemEl.classList.add('is-safe');
    }

    // Determine Status Badge Markup
    let badgeClass = 'badge-safe';
    let badgeLabel = 'SAFE';

    if (isSuppressed) {
      badgeClass = 'badge-suppressed';
      badgeLabel = 'SUPPRESSED';
    } else if (isMalicious) {
      badgeClass = 'badge-malicious';
      badgeLabel = 'MALICIOUS';
    } else if (isUnknown) {
      badgeClass = 'badge-unknown';
      badgeLabel = 'UNKNOWN';
    }

    // Risk Score
    const displayRiskScore = isMalicious ? 100 : 0;
    const scoreBadgeClass = displayRiskScore === 100 ? 'score-100' : 'score-0';

    // Header Content
    const DEFAULT_FAVICON = 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%2394a3b8"><circle cx="12" cy="12" r="10"/></svg>';
    const rawFavicon = tab.favIconUrl || '';
    const tabFavicon = (/^(https?:\/\/|data:image\/|chrome:\/\/favicon\/)/i.test(rawFavicon)) ? rawFavicon : DEFAULT_FAVICON;
    const tabHostname = getHostname(tab.url);

    // Build Evidence HTML (for malicious)
    let evidenceHtml = '';
    if (verdict.evidence && verdict.evidence.length > 0) {
      const items = verdict.evidence.map(e => `<li>${escapeHtml(e)}</li>`).join('');
      evidenceHtml = `
        <div class="section-heading">Threat Evidence</div>
        <ul class="evidence-list">${items}</ul>
      `;
    }

    // Build Unverified Sources HTML (for unknown)
    let unverifiedHtml = '';
    if (verdict.unverifiedBy && verdict.unverifiedBy.length > 0) {
      const items = verdict.unverifiedBy.map(u => `<li>Unverified by: ${escapeHtml(u)}</li>`).join('');
      unverifiedHtml = `
        <div class="section-heading">Unverified Intelligence Sources</div>
        <ul class="unverified-list">${items}</ul>
      `;
    }

    // Build Notes HTML
    let notesHtml = '';
    if (verdict.notes && verdict.notes.length > 0) {
      const items = verdict.notes.map(n => `<li>${escapeHtml(n)}</li>`).join('');
      notesHtml = `
        <div class="section-heading">Diagnostics & Notes</div>
        <ul class="notes-list">${items}</ul>
      `;
    }

    // Remediation Buttons
    const fpButtonHtml = (isMalicious || isUnknown) ? `
      <button class="btn-action btn-report-fp" data-tab-id="${tab.id}" title="Copy threat telemetry to clipboard and suppress future alerts">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
        </svg>
        <span>Report False Positive</span>
      </button>
    ` : '';

    itemEl.innerHTML = `
      <div class="accordion-header">
        <div class="tab-meta">
          <img class="tab-favicon" src="${escapeHtml(tabFavicon)}" alt="">
          <div class="tab-info">
            <span class="tab-title-line" title="${escapeHtml(tab.title || tab.url)}">${escapeHtml(tab.title || 'Untitled Tab')}</span>
            <span class="tab-domain-line">${escapeHtml(tabHostname)}</span>
          </div>
        </div>
        <div class="tab-badge-group">
          <span class="verdict-badge ${badgeClass}">${badgeLabel}</span>
          <svg class="chevron-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="6 9 12 15 18 9"></polyline>
          </svg>
        </div>
      </div>
      <div class="accordion-body">
        <div class="score-row">
          <span class="score-label">Risk Score</span>
          <span class="score-badge ${scoreBadgeClass}">${displayRiskScore} / 100</span>
        </div>
        <div class="url-display-box" title="${escapeHtml(tab.url)}">${escapeHtml(tab.url)}</div>
        ${evidenceHtml}
        ${unverifiedHtml}
        ${notesHtml}
        <div class="remediation-actions">
          <button class="btn-action btn-close-tab" data-tab-id="${tab.id}" title="Instantly terminate this browser tab">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
            <span>Close Tab</span>
          </button>
          ${fpButtonHtml}
        </div>
      </div>
    `;

    // Hook: Favicon fallback without inline onerror (CSP Compliant)
    const faviconImg = itemEl.querySelector('.tab-favicon');
    if (faviconImg) {
      faviconImg.addEventListener('error', () => {
        faviconImg.src = DEFAULT_FAVICON;
      });
    }

    // Hook: Accordion toggle
    const headerEl = itemEl.querySelector('.accordion-header');
    headerEl.addEventListener('click', (e) => {
      // Don't toggle if clicking a button inside header
      itemEl.classList.toggle('is-open');
    });

    // Hook: Close Tab Button
    const btnClose = itemEl.querySelector('.btn-close-tab');
    if (btnClose) {
      btnClose.addEventListener('click', async (e) => {
        e.stopPropagation();
        await handleCloseTab(tab.id, itemEl);
      });
    }

    // Hook: Report False Positive Button
    const btnFp = itemEl.querySelector('.btn-report-fp');
    if (btnFp) {
      btnFp.addEventListener('click', async (e) => {
        e.stopPropagation();
        await handleReportFalsePositive(tab, verdict, itemEl);
      });
    }

    elList.appendChild(itemEl);
  }

  if (visibleCount === 0) {
    elEmpty.classList.remove('hidden');
  }
}

/**
 * Functional Remediation Hook 1: Close Tab
 * Calls chrome.tabs.remove(tabId) and dynamically removes the row from the DOM.
 */
async function handleCloseTab(tabId, itemEl) {
  try {
    // 1. Remove browser tab via Chrome Extension API
    await chrome.tabs.remove(tabId);

    // 2. Animate and remove row from DOM
    itemEl.classList.add('is-removing');
    setTimeout(() => {
      itemEl.remove();

      // Update state arrays
      state.tabs = state.tabs.filter(t => t.id !== tabId);
      state.triageData.delete(tabId);

      // Refresh metrics
      updateMetrics();

      if (state.tabs.length === 0) {
        elEmpty.classList.remove('hidden');
      }
    }, 200);

    showToast('Tab closed successfully.');
  } catch (err) {
    console.error('[Close Tab Error]', err);
    showToast(`Could not close tab: ${err.message}`);
  }
}

/**
 * Functional Remediation Hook 2: Report False Positive
 * Writes threat data to clipboard via navigator.clipboard.writeText.
 * Messages background.js worker to add URL to local suppression list.
 */
async function handleReportFalsePositive(tab, verdict, itemEl) {
  try {
    // 1. Construct threat telemetry report object
    const threatReport = {
      reportType: "PhishGuard_False_Positive_Submission",
      submittedAt: new Date().toISOString(),
      tabId: tab.id,
      url: tab.url,
      title: tab.title,
      verdict: {
        status: verdict.status,
        riskScore: verdict.riskScore,
        evidence: verdict.evidence || [],
        notes: verdict.notes || [],
        unverifiedBy: verdict.unverifiedBy || []
      },
      clientContext: {
        userAgent: navigator.userAgent,
        source: "PhishGuard Web SOC Console"
      }
    };

    const serializedReport = JSON.stringify(threatReport, null, 2);

    // 2. Write threat data to user's clipboard
    await navigator.clipboard.writeText(serializedReport);

    // 3. Message background worker to add to suppression list
    await chrome.runtime.sendMessage({
      action: 'SUPPRESS_URL',
      url: tab.url,
      tabId: tab.id
    });

    const normUrl = (tab.url || '').split('#')[0];
    if (!state.suppressionList.includes(normUrl)) {
      state.suppressionList.push(normUrl);
    }

    // 4. Update UI card presentation immediately
    itemEl.classList.remove('is-malicious');
    itemEl.classList.add('is-suppressed');

    const badgeEl = itemEl.querySelector('.verdict-badge');
    if (badgeEl) {
      badgeEl.className = 'verdict-badge badge-suppressed';
      badgeEl.textContent = 'SUPPRESSED';
    }

    // Update summary metrics
    updateMetrics();

    // 5. User confirmation toast
    showToast('Threat report copied to clipboard! URL suppressed from alerts.');

  } catch (err) {
    console.error('[False Positive Error]', err);
    showToast(`Clipboard write failed: ${err.message}`);
  }
}

// -----------------------------------------------------------------------------
// Event Bindings
// -----------------------------------------------------------------------------

// Rescan Open Tabs button
elBtnRescan.addEventListener('click', async () => {
  await loadAndTriageTabs(true);
  showToast('Rescanned all open tabs.');
});

// Filter tabs
filterButtons.forEach(btn => {
  btn.addEventListener('click', () => {
    filterButtons.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.currentFilter = btn.dataset.filter;
    renderAccordionList();
  });
});

// Initial boot
document.addEventListener('DOMContentLoaded', async () => {
  await checkBackendHealth();
  await loadAndTriageTabs(false);
});
