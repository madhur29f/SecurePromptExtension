/**
 * SecurePrompt — Content Script
 * Intercepts text input, file uploads, and paste events on AI chat platforms.
 * Scans for PII and shows warning modal before submission.
 */

(async () => {
  'use strict';

  // ── Settings ──
  let settings = { enabled: true, autoRedact: false, enabledTypes: null };

  try {
    const stored = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
    if (stored) {
      settings.enabled = stored.enabled !== false;
      settings.autoRedact = stored.autoRedact || false;
      settings.enabledTypes = stored.enabledTypes || null;
    }
  } catch (e) {
    // Use defaults
  }

  // Listen for settings changes
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.enabled) settings.enabled = changes.enabled.newValue;
    if (changes.autoRedact) settings.autoRedact = changes.autoRedact.newValue;
    if (changes.enabledTypes) settings.enabledTypes = changes.enabledTypes.newValue;
  });

  // ── Platform detection ──
  const hostname = window.location.hostname;
  let platform = 'unknown';

  if (hostname.includes('chatgpt.com') || hostname.includes('chat.openai.com')) {
    platform = 'chatgpt';
  } else if (hostname.includes('claude.ai')) {
    platform = 'claude';
  } else if (hostname.includes('gemini.google.com')) {
    platform = 'gemini';
  }

  console.log(`[SecurePrompt] Active on ${platform} (${hostname})`);

  // ── Selectors per platform ──
  const SELECTORS = {
    chatgpt: {
      textInput: '#prompt-textarea, div[contenteditable="true"][id="prompt-textarea"], div.ProseMirror',
      sendButton: 'button[data-testid="send-button"], button[aria-label="Send prompt"], form button[type="submit"]',
      fileInput: 'input[type="file"]',
      form: 'form',
      // Tight selectors — only match actual file attachment UI, not avatars
      attachmentIndicators: [
        'button[aria-label="Remove file"]',
        '[data-testid="attachment-thumbnail"]',
        '[data-testid="file-thumbnail"]',
      ]
    },
    claude: {
      textInput: 'div.ProseMirror[contenteditable="true"], div[contenteditable="true"].is-editor-empty, fieldset div[contenteditable="true"]',
      sendButton: 'button[aria-label="Send Message"], button[aria-label="Send message"], fieldset button:last-of-type',
      fileInput: 'input[type="file"]',
      form: 'form, fieldset',
      attachmentIndicators: [
        'button[aria-label="Remove file"]',
        'button[aria-label="Remove attachment"]',
        '[class*="FileCard"]',
        '[class*="file-card"]',
      ]
    },
    gemini: {
      textInput: 'div.ql-editor[contenteditable="true"], rich-textarea div[contenteditable="true"], div.text-input-field_textarea[contenteditable="true"]',
      sendButton: 'button.send-button, button[aria-label="Send message"], button[data-id="send-button"]',
      fileInput: 'input[type="file"]',
      form: 'form',
      attachmentIndicators: [
        '[class*="file-chip"]',
        'button[aria-label="Remove file"]',
      ]
    },
    unknown: {
      textInput: 'div[contenteditable="true"], textarea',
      sendButton: 'button[type="submit"]',
      fileInput: 'input[type="file"]',
      form: 'form',
      attachmentIndicators: []
    }
  };

  const sel = SELECTORS[platform] || SELECTORS.unknown;

  // ── State ──
  let pendingFiles = [];           // Raw File objects captured from events
  let pendingScanResults = [];     // Pre-scanned file results ready for modal
  let isProcessing = false;
  let observerActive = false;
  let bypassNext = false;          // Skip interception for the next send (after Redact/Send Anyway)

  // ── Helper: Get text from input element ──
  function getInputText(el) {
    if (!el) return '';
    if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') {
      return el.value || '';
    }
    return el.innerText || el.textContent || '';
  }

  // ── Helper: Set text in input element ──
  function setInputText(el, text) {
    if (!el) return;
    if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') {
      const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype, 'value'
      )?.set || Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype, 'value'
      )?.set;

      if (nativeInputValueSetter) {
        nativeInputValueSetter.call(el, text);
      } else {
        el.value = text;
      }
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    } else {
      el.focus();
      const paragraphs = el.querySelectorAll('p');
      if (paragraphs.length > 0) {
        paragraphs[0].textContent = text;
        for (let i = 1; i < paragraphs.length; i++) {
          paragraphs[i].remove();
        }
      } else {
        el.textContent = text;
      }
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new InputEvent('input', {
        bubbles: true,
        inputType: 'insertText',
        data: text
      }));
    }
  }

  // ── Helper: Find the active text input ──
  function findTextInput() {
    const inputs = document.querySelectorAll(sel.textInput);
    for (const input of inputs) {
      if (input.offsetParent !== null) return input;
    }
    return inputs[0] || null;
  }

  // ── Helper: Find the send button ──
  function findSendButton() {
    const buttons = document.querySelectorAll(sel.sendButton);
    for (const btn of buttons) {
      if (btn.offsetParent !== null) return btn;
    }
    return buttons[0] || null;
  }

  // ──────────────────────────────────────────────────────────
  //  FILE DETECTION — NEW STRATEGY
  //
  //  1) "change" / "paste" / "drop" events → capture File
  //     objects and scan them IMMEDIATELY. Store results in
  //     pendingScanResults[].
  //
  //  2) The MAIN-world helper (page-intercept.js) listens to
  //     FormData.append in the page's real JS context and
  //     posts File metadata back to us via window messages.
  //
  //  3) DOM-based fallback: when Send is clicked, we check
  //     attachment-indicator selectors. If any match and we
  //     have NO scan results, we inject a generic warning.
  // ──────────────────────────────────────────────────────────

  // ── Core: Scan Text and Intercept Send ──
  async function interceptTextAndScan(triggerEvent, triggerElement) {
    if (!settings.enabled || isProcessing) return;
    isProcessing = true;

    try {
      const textInput = findTextInput();
      const text = getInputText(textInput);

      // Scan text only (files are now completely handled at the attachment phase)
      const textFindings = (text && text.trim().length > 0)
        ? PIIDetector.scan(text, settings.enabledTypes)
        : [];

      if (textFindings.length === 0) {
        isProcessing = false;
        return;
      }

      // Block the send event
      if (triggerEvent) {
        triggerEvent.preventDefault();
        triggerEvent.stopImmediatePropagation();
        triggerEvent.stopPropagation();
      }

      chrome.runtime.sendMessage({ type: 'PII_DETECTED', count: textFindings.length, platform });

      // Auto-redact mode
      if (settings.autoRedact) {
        const allIndices = new Set(textFindings.map((_, i) => i));
        const redactedText = PIIDetector.redact(text, textFindings, allIndices);
        setInputText(textInput, redactedText);

        chrome.runtime.sendMessage({ type: 'PII_REDACTED', count: textFindings.length });

        isProcessing = false;
        bypassNext = true;
        const sendBtn = findSendButton();
        if (sendBtn) setTimeout(() => sendBtn.click(), 100);
        return;
      }

      // Show modal
      const result = await SecurePromptModal.show({ 
        textFindings, 
        fileResults: [],
        allowFileRedaction: false 
      });

      switch (result.action) {
        case 'redact': {
          if (result.selectedIndices.size > 0) {
            const redactedText = PIIDetector.redact(text, textFindings, result.selectedIndices);
            setInputText(textInput, redactedText);
            chrome.runtime.sendMessage({ type: 'PII_REDACTED', count: result.selectedIndices.size });
          }
          isProcessing = false;
          bypassNext = true;
          const sendBtn = findSendButton();
          if (sendBtn) setTimeout(() => sendBtn.click(), 150);
          break;
        }
        case 'send': {
          isProcessing = false;
          bypassNext = true;
          const sendBtn2 = findSendButton();
          if (sendBtn2) setTimeout(() => sendBtn2.click(), 150);
          break;
        }
        case 'cancel':
        default:
          chrome.runtime.sendMessage({ type: 'PII_BLOCKED' });
          isProcessing = false;
          break;
      }
    } catch (err) {
      console.error('[SecurePrompt] Error during text scan:', err);
      isProcessing = false;
    }
  }

  // ── Send Handlers ──

  document.addEventListener('click', (e) => {
    if (!settings.enabled || isProcessing) return;
    if (bypassNext) { bypassNext = false; return; }

    const sendBtn = e.target.closest(sel.sendButton);
    if (!sendBtn) return;

    const textInput = findTextInput();
    const text = getInputText(textInput);

    if (!text) return;

    const quickFindings = PIIDetector.scan(text, settings.enabledTypes);
    if (quickFindings.length === 0) return;

    e.preventDefault();
    e.stopImmediatePropagation();
    e.stopPropagation();

    interceptTextAndScan(null, sendBtn);
  }, true);

  document.addEventListener('keydown', (e) => {
    if (!settings.enabled || isProcessing) return;
    if (bypassNext) { bypassNext = false; return; }
    if (e.key !== 'Enter' || e.shiftKey) return;

    const textInput = findTextInput();
    if (!textInput || !textInput.contains(e.target)) return;

    const text = getInputText(textInput);
    if (!text) return;

    const quickFindings = PIIDetector.scan(text, settings.enabledTypes);
    if (quickFindings.length === 0) return;

    e.preventDefault();
    e.stopImmediatePropagation();
    e.stopPropagation();

    interceptTextAndScan(null, textInput);
  }, true);

  document.addEventListener('submit', (e) => {
    if (!settings.enabled || isProcessing) return;
    if (bypassNext) { bypassNext = false; return; }

    const textInput = findTextInput();
    const text = getInputText(textInput);

    if (!text) return;

    const quickFindings = PIIDetector.scan(text, settings.enabledTypes);
    if (quickFindings.length === 0) return;

    e.preventDefault();
    e.stopImmediatePropagation();

    interceptTextAndScan(null, null);
  }, true);


  // ──────────────────────────────────────────────────────────
  //  FILE ATTACHMENT INTERCEPTION (DOM SPOOFING)
  //
  //  Intercept event, scan, popup inline.
  //  If cleared/redacted, we construct a DataTransfer and 
  //  replay a synthetic event with the safe payload.
  // ──────────────────────────────────────────────────────────

  async function handleFileEventInterception(files, triggerEvent, replayerCallback) {
    if (files.length === 0) return;
    console.log(`[SecurePrompt] Intercepted ${files.length} file(s) for scan.`);
    
    // Scan files
    const fileResults = await FileScanner.scanFiles(files);
    
    const hasFindings = fileResults.some(fr => 
      (fr.findings && fr.findings.length > 0) || 
      (fr.warnings && fr.warnings.length > 0 && fr.warnings[0].source !== 'visual')
    );
    
    const isJustGenericImageWarning = fileResults.every(fr => 
      (!fr.findings || fr.findings.length === 0) &&
      (!fr.warnings || fr.warnings.length === 0 || (fr.warnings.length === 1 && fr.warnings[0].source === 'visual'))
    );

    // If completely clean or just generic image warning, replay original files immediately
    if (!hasFindings && !isJustGenericImageWarning) {
      replayerCallback(files);
      return;
    }
    if (isJustGenericImageWarning) {
      replayerCallback(files);
      return;
    }

    // Has PII! Show modal
    const decision = await SecurePromptModal.show({ 
      textFindings: [], 
      fileResults, 
      allowFileRedaction: true 
    });

    if (decision.action === 'cancel') {
      console.log('[SecurePrompt] File attach cancelled.');
      // Do nothing, event is already blocked
    } else if (decision.action === 'send') {
      // Send anyway -> replay with original files
      replayerCallback(files);
    } else if (decision.action === 'redact') {
      // Redact selected files
      const finalFiles = [];
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const res = fileResults[i];
        if (res.findings && res.findings.length > 0) {
          const redacted = await FileScanner.redactFile(file, res, decision.selectedIndices);
          finalFiles.push(redacted);
        } else {
          finalFiles.push(file); // No findings = keep original
        }
      }
      replayerCallback(finalFiles);
    }
  }

  // 4. Intercept file inputs
  document.addEventListener('change', async (e) => {
    if (e._isSecurePromptReplay_ || !settings.enabled) return;
    if (e.target.tagName !== 'INPUT' || e.target.type !== 'file') return;

    const files = Array.from(e.target.files || []);
    if (files.length === 0) return;

    // Block original event
    e.preventDefault();
    e.stopImmediatePropagation();
    e.stopPropagation();

    const target = e.target;
    
    await handleFileEventInterception(files, e, (finalFiles) => {
      try {
        const dt = new DataTransfer();
        finalFiles.forEach(f => dt.items.add(f));
        target.files = dt.files;
        
        // Replay synthetic change event
        const newEvent = new Event('change', { bubbles: true });
        newEvent._isSecurePromptReplay_ = true;
        target.dispatchEvent(newEvent);
      } catch (err) {
        console.error('[SecurePrompt] Could not spoof change event', err);
      }
    });
  }, true);

  // 5. Intercept Paste
  document.addEventListener('paste', async (e) => {
    if (e._isSecurePromptReplay_ || !settings.enabled) return;

    const items = e.clipboardData?.items;
    const pastedFiles = [];
    if (items) {
      for (const item of items) {
        if (item.kind === 'file') {
          const file = item.getAsFile();
          if (file) pastedFiles.push(file);
        }
      }
    }

    if (pastedFiles.length > 0) {
      e.preventDefault();
      e.stopImmediatePropagation();
      e.stopPropagation();
      
      const target = e.target;
      const originalText = e.clipboardData?.getData('text/plain') || '';

      await handleFileEventInterception(pastedFiles, e, (finalFiles) => {
        try {
          const dt = new DataTransfer();
          finalFiles.forEach(f => dt.items.add(f));
          if (originalText) dt.setData('text/plain', originalText);
          
          const pasteEvent = new ClipboardEvent('paste', {
            bubbles: true, cancelable: true,
            clipboardData: dt
          });
          pasteEvent._isSecurePromptReplay_ = true;
          target.dispatchEvent(pasteEvent);
        } catch (err) {
          console.error('[SecurePrompt] Could not spoof paste event', err);
        }
      });
      return; // Handled files
    }

    // Text-only paste: just scan silently, send button will catch it later
    const pastedText = e.clipboardData?.getData('text/plain') || '';
    if (pastedText) {
      const findings = PIIDetector.scan(pastedText, settings.enabledTypes);
      if (findings.length > 0) console.log(`[SecurePrompt] Pasted text contains ${findings.length} PII item(s)`);
    }
  }, true);

  // 6. Intercept Drop
  document.addEventListener('drop', async (e) => {
    if (e._isSecurePromptReplay_ || !settings.enabled) return;

    const files = Array.from(e.dataTransfer?.files || []);
    if (files.length === 0) return;

    e.preventDefault();
    e.stopImmediatePropagation();
    e.stopPropagation();

    const target = e.target;

    await handleFileEventInterception(files, e, (finalFiles) => {
      try {
        const dt = new DataTransfer();
        finalFiles.forEach(f => dt.items.add(f));
        
        const dropEvent = new DragEvent('drop', {
          bubbles: true, cancelable: true,
          dataTransfer: dt,
          clientX: e.clientX, clientY: e.clientY
        });
        dropEvent._isSecurePromptReplay_ = true;
        target.dispatchEvent(dropEvent);
      } catch (err) {
        console.error('[SecurePrompt] Could not spoof drop event', err);
      }
    });
  }, true);

  // ──────────────────────────────────────────────────────────
  //  LIVE SPEEDOMETER RISK GAUGE
  // ──────────────────────────────────────────────────────────
  let riskGaugeEl = null;
  let riskRingFill = null;
  let riskText = null;

  function initRiskGauge() {
    if (riskGaugeEl && document.body.contains(riskGaugeEl)) return;
    const input = findTextInput();
    if (!input || !input.parentElement) return;

    riskGaugeEl = document.createElement('div');
    riskGaugeEl.className = 'secureprompt-risk-gauge';
    riskGaugeEl.innerHTML = `
      <svg width="32" height="32" viewBox="0 0 32 32">
        <circle class="secureprompt-risk-ring-bg" cx="16" cy="16" r="13"></circle>
        <circle class="secureprompt-risk-ring-fill" cx="16" cy="16" r="13"></circle>
        <text class="secureprompt-risk-text" x="16" y="17">0</text>
      </svg>
    `;
    const parent = input.parentElement;
    if (window.getComputedStyle(parent).position === 'static') {
      parent.style.position = 'relative';
    }
    parent.appendChild(riskGaugeEl);
    riskRingFill = riskGaugeEl.querySelector('.secureprompt-risk-ring-fill');
    riskText = riskGaugeEl.querySelector('.secureprompt-risk-text');
  }

  function updateRiskGauge(score) {
    initRiskGauge();
    if (!riskGaugeEl) return;

    if (score > 0) {
      riskGaugeEl.classList.add('sp-visible');
    }


    const circumference = 81.68;
    const offset = Math.max(0, circumference - (score / 100) * circumference);
    riskRingFill.style.strokeDasharray = circumference;
    riskRingFill.style.strokeDashoffset = offset;
    riskText.textContent = score;

    let color = '#00ff41'; // Green
    if (score >= 90) color = '#ff3131'; // Red
    else if (score >= 40) color = '#ffd700'; // Yellow

    riskGaugeEl.style.setProperty('--risk-color', color);

    if (score >= 90) {
      riskGaugeEl.classList.add('secureprompt-critical');
    } else {
      riskGaugeEl.classList.remove('secureprompt-critical');
    }
  }

  let inputDebounceTimer = null;
  function handleLiveInput() {
    clearTimeout(inputDebounceTimer);
    inputDebounceTimer = setTimeout(() => {
      if (!settings.enabled) {
        updateRiskGauge(0);
        return;
      }
      const input = findTextInput();
      if (!input) return;
      const text = getInputText(input);
      if (!text || text.trim() === '') {
        updateRiskGauge(0);
        return;
      }
      if (typeof window.PIIDetector !== 'undefined') {
        const findings = window.PIIDetector.scan(text, settings.enabledTypes);
        const score = window.PIIDetector.calculateRiskScore(findings);
        updateRiskGauge(score);
      }
    }, 200);
  }

  document.addEventListener('input', (e) => {
    const input = findTextInput();
    if (input && input.contains(e.target)) {
      handleLiveInput();
    }
  }, true);

  setInterval(() => {
    if (settings.enabled) initRiskGauge();
  }, 2000);

  console.log('[SecurePrompt] Content script initialized ✓');
})();
