/**
 * SecurePrompt — Background Service Worker
 * Manages extension badge, storage, and message passing.
 */

// Initialize default settings on install
chrome.runtime.onInstalled.addListener(async () => {
  const defaults = {
    enabled: true,
    autoRedact: false,
    stats: {
      totalDetected: 0,
      totalRedacted: 0,
      totalBlocked: 0,
      sessionsProtected: 0,
      todayDetected: 0,
      todayDate: new Date().toDateString()
    },
    enabledTypes: null // null = all types enabled
  };

  const existing = await chrome.storage.local.get(null);
  if (!existing.enabled && existing.enabled !== false) {
    await chrome.storage.local.set(defaults);
  }

  // Set initial badge
  chrome.action.setBadgeBackgroundColor({ color: '#22c55e' });
  chrome.action.setBadgeText({ text: '' });
});

// Handle messages from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case 'PII_DETECTED':
      handlePIIDetected(message, sender.tab);
      break;

    case 'PII_REDACTED':
      handlePIIRedacted(message);
      break;

    case 'PII_BLOCKED':
      handlePIIBlocked(message);
      break;

    case 'GET_SETTINGS':
      chrome.storage.local.get(null).then(sendResponse);
      return true; // async

    case 'UPDATE_SETTINGS':
      chrome.storage.local.set(message.settings).then(() => sendResponse({ ok: true }));
      return true;

    case 'GET_STATS':
      chrome.storage.local.get('stats').then(sendResponse);
      return true;

    case 'RESET_STATS':
      const freshStats = {
        totalDetected: 0,
        totalRedacted: 0,
        totalBlocked: 0,
        sessionsProtected: 0,
        todayDetected: 0,
        todayDate: new Date().toDateString()
      };
      chrome.storage.local.set({ stats: freshStats }).then(() => sendResponse({ ok: true }));
      return true;

    case 'OCR_IMAGE':
      handleOCRRequest(message, sendResponse);
      return true;
  }
});

let creatingOffscreen;
async function setupOffscreenDocument(path) {
  const offscreenUrl = chrome.runtime.getURL(path);
  
  if (chrome.runtime.getContexts) {
    const existingContexts = await chrome.runtime.getContexts({
      contextTypes: ['OFFSCREEN_DOCUMENT'],
      documentUrls: [offscreenUrl]
    });
    if (existingContexts.length > 0) return;
  }

  if (creatingOffscreen) {
    await creatingOffscreen;
    return;
  }
  
  creatingOffscreen = chrome.offscreen.createDocument({
    url: path,
    reasons: ['DOM_PARSER'],
    justification: 'Run Tesseract.js OCR offline without violating host page CSP',
  });
  
  await creatingOffscreen;
  creatingOffscreen = null;
}

async function handleOCRRequest(message, sendResponse) {
  try {
    await setupOffscreenDocument('offscreen.html');
    const result = await chrome.runtime.sendMessage({
      target: 'offscreen',
      type: 'OCR_IMAGE',
      dataUrl: message.dataUrl
    });
    sendResponse(result);
  } catch (err) {
    console.error('[SecurePrompt Background] OCR Setup Error:', err);
    sendResponse({ error: err.toString() });
  }
}

async function handlePIIDetected(message, tab) {
  const { stats = {} } = await chrome.storage.local.get('stats');

  // Reset daily counter if new day
  if (stats.todayDate !== new Date().toDateString()) {
    stats.todayDetected = 0;
    stats.todayDate = new Date().toDateString();
  }

  const count = message.count || 1;
  stats.totalDetected = (stats.totalDetected || 0) + count;
  stats.todayDetected = (stats.todayDetected || 0) + count;

  await chrome.storage.local.set({ stats });

  // Update badge
  if (tab?.id) {
    chrome.action.setBadgeBackgroundColor({ color: '#ef4444', tabId: tab.id });
    chrome.action.setBadgeText({ text: String(stats.todayDetected), tabId: tab.id });
  }
}

async function handlePIIRedacted(message) {
  const { stats = {} } = await chrome.storage.local.get('stats');
  stats.totalRedacted = (stats.totalRedacted || 0) + (message.count || 1);
  await chrome.storage.local.set({ stats });
}

async function handlePIIBlocked(message) {
  const { stats = {} } = await chrome.storage.local.get('stats');
  stats.totalBlocked = (stats.totalBlocked || 0) + 1;
  await chrome.storage.local.set({ stats });
}
