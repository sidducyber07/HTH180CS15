// ============================================================================
// BACKEND CONTRACT
// Each returned tab must include: id (number), title (string), url (string),
// status ("safe" | "malicious" | "pending"), riskScore (number), and
// evidence (array of strings). The API may return the array directly or as
// { tabs: [...] }. No local/demo tab records are loaded in this popup.
// ============================================================================

// The popup talks only to the local backend; threat-feed checks run server-side.
const BACKEND_CONFIG = {
  endpoint: "http://127.0.0.1:8787/api/analyze"
};

// The backend response replaces this empty array after a successful request.
let tabsData = [];

// Get the HTML element where renderTabs() inserts all tab accordion items.
const tabsContainer = document.getElementById("tabs-container");
// Get the small label used to show the number of tabs found.
const tabCount = document.getElementById("tab-count");
// Get the scan button so it can launch the backend analysis request.
const analyzeButton = document.getElementById("analyze-button");

// Convert untrusted backend text to HTML-safe text before inserting it into markup.
function escapeHTML(value) {
  // Replace HTML-sensitive characters with their safe entity equivalents.
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", // Prevent an ampersand from starting an HTML entity.
    "<": "&lt;", // Prevent text from being interpreted as an HTML tag.
    ">": "&gt;", // Prevent text from ending or forming an HTML tag.
    '"': "&quot;", // Keep double quotes from escaping HTML attributes.
    "'": "&#39;" // Keep single quotes from escaping HTML attributes.
  })[character]); // Return the escaped replacement for the matched character.
}

// Return the inline SVG icon that corresponds to a tab's analysis status.
function getStatusIcon(status) {
  // Malicious tabs use a red circle with an X mark.
  if (status === "malicious") {
    return `<svg class="status-icon status-malicious" viewBox="0 0 20 20" fill="none" aria-label="Malicious" xmlns="http://www.w3.org/2000/svg">
      <circle cx="10" cy="10" r="8" fill="currentColor" fill-opacity=".13"/>
      <path d="m7 7 6 6m0-6-6 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
    </svg>`;
  }

  // Pending tabs use a partial circle; CSS rotates it to create a spinner.
  if (status === "pending") {
    return `<svg class="status-icon status-pending" viewBox="0 0 20 20" fill="none" aria-label="Analysis pending" xmlns="http://www.w3.org/2000/svg">
      <circle cx="10" cy="10" r="7.5" stroke="currentColor" stroke-opacity=".26" stroke-width="2"/>
      <path d="M10 2.5A7.5 7.5 0 0 1 17.5 10" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
    </svg>`;
  }

  // All other statuses use the green check icon for a safe tab.
  return `<svg class="status-icon status-safe" viewBox="0 0 20 20" fill="none" aria-label="Safe" xmlns="http://www.w3.org/2000/svg">
    <circle cx="10" cy="10" r="8" fill="currentColor" fill-opacity=".13"/>
    <path d="m6.2 10.1 2.5 2.5 5.2-5.3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;
}

// Turn an evidence array into safe, warning-icon list markup.
function getEvidenceMarkup(evidence, status) {
  // Show a real pending state rather than implying an unfinished scan is safe.
  if (!evidence.length && status === "pending") {
    return `<p class="no-evidence">Threat-feed lookup is still processing.</p>`;
  }

  // A completed report with no detections is described as provider results, not certainty.
  if (!evidence.length) {
    return `<p class="no-evidence">No matches in the configured threat feeds.</p>`;
  }

  // Escape every backend evidence string before placing it in the HTML template.
  const items = evidence.map((item) => `
    <li>
      <svg class="evidence-icon" viewBox="0 0 16 16" fill="none" aria-hidden="true" xmlns="http://www.w3.org/2000/svg">
        <path d="M8 1.8 14.2 13H1.8L8 1.8Z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/>
        <path d="M8 5.4v3.3m0 1.7h.01" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      </svg>
      <span>${escapeHTML(item)}</span>
    </li>`).join(""); // Join all generated list items into one HTML string.

  // Wrap the generated list items in the styled evidence-list container.
  return `<ul class="evidence-list">${items}</ul>`;
}

// Generate all accordion rows from tabsData and put them into the popup DOM.
function renderTabs() {
  // Stop safely if this script is loaded on a page without the expected container.
  if (!tabsContainer) return;

  // Update the visible count label from the current backend result count.
  tabCount.textContent = `${tabsData.length} detected`;

  // Show an honest empty state until the backend returns real scan results.
  if (tabsData.length === 0) {
    tabsContainer.innerHTML = '<p class="empty-state">No backend results yet. Select Analyze Open Tabs to scan.</p>';
    return;
  }

  // Convert every backend tab record into its corresponding accordion markup.
  tabsContainer.innerHTML = tabsData.map((tab) => {
    // Escape backend-provided strings before inserting them into HTML text nodes.
    const title = escapeHTML(tab.title);
    const url = escapeHTML(tab.url);
    // Create a unique details-panel ID; Number() keeps the ID safe and predictable.
    const panelId = `tab-details-${Number(tab.id)}`;
    // Set a boolean used for malicious-only styling and risk badge output.
    const isMalicious = tab.status === "malicious";
    // Convert the raw backend status to a short accessible label.
    const statusLabel = tab.status === "malicious" ? "Malicious" : tab.status === "pending" ? "Analyzing" : "Safe";

    // Return one complete tab row: trigger button followed by the expandable details.
    return `
      <article class="tab-item${isMalicious ? " is-malicious" : ""}" data-tab-id="${Number(tab.id)}">
        <button class="tab-trigger" type="button" aria-expanded="false" aria-controls="${panelId}">
          <span class="tab-title-wrap">
            <span class="tab-status">${getStatusIcon(tab.status)}</span>
            <span class="tab-title">${title}</span>
          </span>
          <span class="sr-status" aria-label="${statusLabel}"></span>
          <svg class="chevron" viewBox="0 0 16 16" fill="none" aria-hidden="true" xmlns="http://www.w3.org/2000/svg">
            <path d="m4 6 4 4 4-4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </button>
        <div class="details-shell" id="${panelId}" aria-hidden="true">
          <div class="details-clip">
            <div class="tab-details">
              <div class="detail-divider"></div>
              <div class="detail-header">
                <span class="full-url">${url}</span>
                ${isMalicious ? `<span class="risk-badge">RISK <strong>${Number(tab.riskScore)}</strong></span>` : ""}
              </div>
              <h3 class="evidence-heading">Threat evidence</h3>
              ${getEvidenceMarkup(Array.isArray(tab.evidence) ? tab.evidence : [], tab.status)}
              <div class="action-row">
                <button class="action-button close-tab-button" type="button" data-action="close" data-tab-id="${Number(tab.id)}">Close Tab</button>
                <button class="action-button report-button" type="button" data-action="report" data-tab-id="${Number(tab.id)}">Report False Positive</button>
              </div>
            </div>
          </div>
        </div>
      </article>`;
  }).join(""); // Combine every tab's HTML into one string for the container.
}

// Send the currently open web tabs to the backend and render its scan results.
async function analyzeOpenTabs() {
  // Remember the original button text so it can be restored after the request.
  const buttonLabel = analyzeButton.querySelector("span");
  const originalLabel = buttonLabel.textContent;
  // Give immediate feedback and prevent duplicate requests while scanning.
  analyzeButton.disabled = true;
  buttonLabel.textContent = "Analyzing...";
  tabCount.textContent = "Connecting to backend...";

  try {
    // Stop before making a request if a real endpoint has not been configured.
    if (!BACKEND_CONFIG.endpoint.trim()) {
      throw new Error("Backend endpoint is not configured.");
    }

    // Query current-window tabs; feed credentials, if used, stay on the backend.
    // Read open tabs from this Chrome window; the manifest must grant the tabs permission.
    const openTabs = await chrome.tabs.query({ currentWindow: true });
    // Send only normal web pages and only the fields needed for scanning.
    const tabsToAnalyze = openTabs
      .filter((tab) => Number.isInteger(tab.id) && /^https?:\/\//i.test(tab.url || ""))
      .map((tab) => ({ id: tab.id, title: tab.title || "Untitled tab", url: tab.url }));
    if (!tabsToAnalyze.length) throw new Error("No analyzable web tabs are open.");

    // Send tab metadata to the local backend; external feed credentials never enter the popup.
    const response = await fetch(BACKEND_CONFIG.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tabs: tabsToAnalyze })
    });
    // Read backend error details when available so setup/provider errors are visible.
    if (!response.ok) {
      const errorPayload = await response.json().catch(() => ({}));
      throw new Error(errorPayload.error || `Backend returned HTTP ${response.status}.`);
    }

    // Parse the backend response; it may be an array or an object with a `tabs` array.
    const payload = await response.json();
    const results = Array.isArray(payload) ? payload : payload?.tabs;
    if (!Array.isArray(results)) throw new Error("Backend response must be an array of tab results.");
    // Check the required data contract before rendering any backend-supplied values.
    const validResults = results.every((tab) =>
      tab && Number.isInteger(tab.id) && typeof tab.title === "string" &&
      typeof tab.url === "string" && ["safe", "malicious", "pending"].includes(tab.status) &&
      typeof tab.riskScore === "number" && Array.isArray(tab.evidence) &&
      tab.evidence.every((item) => typeof item === "string")
    );
    if (!validResults) throw new Error("Backend tab results do not match the required data contract.");

    // Replace the current result list with backend records, then regenerate the accordion UI.
    tabsData = results;
    renderTabs();
    tabCount.textContent = `${results.length} analyzed`;
  } catch (error) {
    // Keep the current UI intact and report a concise failure to the user.
    console.error("PhishGuard backend analysis failed:", error);
    tabCount.textContent = error.message || "Backend request failed.";
  } finally {
    // Restore the button whether the request succeeded or failed.
    analyzeButton.disabled = false;
    buttonLabel.textContent = originalLabel;
  }
}

// Hook for future Chrome tab-close integration; add chrome.tabs.remove(tabId) here.
function handleCloseTab(tabId) {}
// Hook for future false-positive reporting; send tabId to your backend here.
function handleReport(tabId) {}

// Listen once on the parent container so it handles clicks on dynamically-rendered items.
tabsContainer.addEventListener("click", (event) => {
  // Find out whether the click came from one of the action buttons.
  const actionButton = event.target.closest("[data-action]");
  // If it was an action button, run its hook and do not also toggle the accordion.
  if (actionButton) {
    event.stopPropagation(); // Prevent the click from reaching the accordion trigger logic.
    const tabId = Number(actionButton.dataset.tabId); // Read the tab ID stored on the button.
    if (actionButton.dataset.action === "close") handleCloseTab(tabId); // Run close hook.
    if (actionButton.dataset.action === "report") handleReport(tabId); // Run report hook.
    return; // Finish handling this click so the detail panel stays open.
  }

  // Otherwise, check if the click came from an accordion header button.
  const trigger = event.target.closest(".tab-trigger");
  if (!trigger) return; // Ignore clicks elsewhere inside the list.

  // Identify the clicked row and remember whether it was already expanded.
  const item = trigger.closest(".tab-item");
  const wasOpen = item.classList.contains("is-open");

  // Close every currently-open row so at most one tab's details are visible.
  tabsContainer.querySelectorAll(".tab-item.is-open").forEach((openItem) => {
    openItem.classList.remove("is-open"); // Remove the CSS class that expands the row.
    openItem.querySelector(".tab-trigger").setAttribute("aria-expanded", "false"); // Update accessibility state.
    openItem.querySelector(".details-shell").setAttribute("aria-hidden", "true"); // Hide details from assistive tech.
  });

  // If the clicked row was closed, open it; if it was open, leave all rows closed.
  if (!wasOpen) {
    item.classList.add("is-open"); // CSS animates this row's details into view.
    trigger.setAttribute("aria-expanded", "true"); // Announce the expanded state accessibly.
    item.querySelector(".details-shell").setAttribute("aria-hidden", "false"); // Expose details to assistive tech.
  }
});

// Connect the Analyze button to the backend request function.
analyzeButton.addEventListener("click", analyzeOpenTabs);

// Render the empty state immediately; successful backend data appears after the scan.
renderTabs();
