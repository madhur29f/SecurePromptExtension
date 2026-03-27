/**
 * SecurePrompt — Modal Controller
 * Injects a clean warning modal into the page when PII is detected.
 * Supports individual item redaction toggles and file warnings.
 */

const SecurePromptModal = (() => {
  let currentResolve = null;
  let overlayElement = null;

  /**
   * Show the PII warning modal.
   * @param {Object} params
   * @param {Array} params.textFindings - PII findings from text
   * @param {Array} params.fileResults - File scan results
   * @returns {Promise<{action: 'redact'|'send'|'cancel', selectedIndices: Set<number>}>}
   */
  function show({ textFindings = [], fileResults = [], allowFileRedaction = false }) {
    return new Promise((resolve) => {
      currentResolve = resolve;

      // Remove existing modal if any
      hide();

      // Count totals
      const totalTextFindings = textFindings.length;
      let totalFileFindings = 0;
      let totalFileWarnings = 0;
      fileResults.forEach(fr => {
        totalFileFindings += (fr.findings || []).length;
        totalFileWarnings += (fr.warnings || []).length;
      });
      const totalFindings = totalTextFindings + totalFileFindings;

      // Build overlay
      overlayElement = document.createElement('div');
      overlayElement.className = 'sp-overlay';
      overlayElement.id = 'sp-modal-overlay';

      // Build modal HTML
      overlayElement.innerHTML = `
        <div class="sp-modal" role="dialog" aria-modal="true" aria-label="Sensitive Data Detected">
          <!-- Header -->
          <div class="sp-header">
            <div class="sp-shield-icon">🛡️</div>
            <div class="sp-header-text">
              <h2>Sensitive Data Detected</h2>
              <p>SecurePrompt found potentially sensitive information in your message.</p>
            </div>
          </div>

          <!-- Stats -->
          <div class="sp-stats">
            ${totalFindings > 0 ? `
              <div class="sp-stat">
                <span>🔍</span>
                <span class="sp-stat-count">${totalFindings}</span>
                <span>PII item${totalFindings !== 1 ? 's' : ''} found</span>
              </div>
            ` : ''}
            ${totalFileWarnings > 0 ? `
              <div class="sp-stat">
                <span>📎</span>
                <span class="sp-stat-count">${fileResults.length}</span>
                <span>file${fileResults.length !== 1 ? 's' : ''} with warnings</span>
              </div>
            ` : ''}
          </div>

          <!-- Body -->
          <div class="sp-body">
            ${totalTextFindings > 0 ? `
              <div class="sp-select-all">
                <button id="sp-select-all-btn">Select All</button>
                <span style="color:#475569;font-size:12px">|</span>
                <button id="sp-deselect-all-btn">Deselect All</button>
              </div>
              <div class="sp-section-label">
                <span>📝</span> Text Content
              </div>
              ${textFindings.map((f, i) => `
                <div class="sp-finding" data-index="${i}">
                  <div class="sp-finding-icon">${f.icon}</div>
                  <div class="sp-finding-info">
                    <div class="sp-finding-type">${escapeHtml(f.label)}</div>
                    <div class="sp-finding-value" title="${escapeHtml(f.value)}">${escapeHtml(f.masked)}</div>
                  </div>
                  <label class="sp-toggle" title="Toggle redaction">
                    <input type="checkbox" checked data-finding-index="${i}">
                    <span class="sp-toggle-track"></span>
                  </label>
                </div>
              `).join('')}
            ` : ''}

            ${fileResults.map((fr, fi) => `
              <div class="sp-section-label">
                <span>📎</span> ${escapeHtml(fr.filename)}
              </div>
              ${(fr.findings || []).map((f, i) => `
                <div class="sp-finding">
                  <div class="sp-finding-icon">${f.icon}</div>
                  <div class="sp-finding-info">
                    <div class="sp-finding-type">${escapeHtml(f.label)}</div>
                    <div class="sp-finding-value">${escapeHtml(f.masked)}</div>
                  </div>
                  ${allowFileRedaction ? `
                  <label class="sp-toggle" title="Toggle redaction">
                    <input type="checkbox" checked data-finding-index="${i}">
                    <span class="sp-toggle-track"></span>
                  </label>
                  ` : ''}
                </div>
              `).join('')}
              ${(fr.warnings || []).map(w => `
                <div class="sp-warning">
                  <div class="sp-warning-icon">⚠️</div>
                  <div class="sp-warning-text">${escapeHtml(w.message)}</div>
                </div>
              `).join('')}
              ${fr.error ? `
                <div class="sp-warning">
                  <div class="sp-warning-icon">❌</div>
                  <div class="sp-warning-text">${escapeHtml(fr.error)}</div>
                </div>
              ` : ''}
            `).join('')}
          </div>

          <!-- Footer -->
          <div class="sp-footer">
            <button class="sp-btn sp-btn-cancel" id="sp-btn-cancel">Cancel</button>
            ${totalFindings > 0 ? `
              <button class="sp-btn sp-btn-anyway" id="sp-btn-anyway">Send Anyway</button>
              <button class="sp-btn sp-btn-redact" id="sp-btn-redact">Redact & Send</button>
            ` : `
              <button class="sp-btn sp-btn-anyway" id="sp-btn-anyway">Send Anyway</button>
            `}
          </div>

          <!-- Confirmation overlay (hidden) -->
          <div class="sp-confirm" id="sp-confirm-overlay" style="display:none">
            <h3>⚠️ Are you sure?</h3>
            <p>Your message contains sensitive data that will be sent unredacted to the AI service. This data may be stored or used for training.</p>
            <div class="sp-confirm-btns">
              <button class="sp-btn sp-btn-cancel" id="sp-confirm-no" style="flex:none;padding:10px 28px">Go Back</button>
              <button class="sp-btn sp-btn-anyway" id="sp-confirm-yes" style="flex:none;padding:10px 28px">Send Unredacted</button>
            </div>
          </div>
        </div>
      `;

      document.body.appendChild(overlayElement);

      // ── Bind events ──
      // Cancel
      overlayElement.querySelector('#sp-btn-cancel')?.addEventListener('click', () => {
        resolveWith({ action: 'cancel', selectedIndices: new Set() });
      });

      // Redact & Send
      overlayElement.querySelector('#sp-btn-redact')?.addEventListener('click', () => {
        const selected = getSelectedIndices();
        resolveWith({ action: 'redact', selectedIndices: selected });
      });

      // Send Anyway → show confirmation
      overlayElement.querySelector('#sp-btn-anyway')?.addEventListener('click', () => {
        const confirmEl = overlayElement.querySelector('#sp-confirm-overlay');
        if (confirmEl) confirmEl.style.display = 'flex';
      });

      // Confirm: yes
      overlayElement.querySelector('#sp-confirm-yes')?.addEventListener('click', () => {
        resolveWith({ action: 'send', selectedIndices: new Set() });
      });

      // Confirm: no (go back)
      overlayElement.querySelector('#sp-confirm-no')?.addEventListener('click', () => {
        const confirmEl = overlayElement.querySelector('#sp-confirm-overlay');
        if (confirmEl) confirmEl.style.display = 'none';
      });

      // Select all / deselect all
      overlayElement.querySelector('#sp-select-all-btn')?.addEventListener('click', () => {
        overlayElement.querySelectorAll('.sp-toggle input[type="checkbox"]').forEach(cb => cb.checked = true);
      });
      overlayElement.querySelector('#sp-deselect-all-btn')?.addEventListener('click', () => {
        overlayElement.querySelectorAll('.sp-toggle input[type="checkbox"]').forEach(cb => cb.checked = false);
      });

      // Close on overlay click (outside modal)
      overlayElement.addEventListener('click', (e) => {
        if (e.target === overlayElement) {
          resolveWith({ action: 'cancel', selectedIndices: new Set() });
        }
      });

      // ESC key
      document.addEventListener('keydown', onKeyDown);
    });
  }

  function getSelectedIndices() {
    const indices = new Set();
    if (!overlayElement) return indices;
    overlayElement.querySelectorAll('.sp-toggle input[type="checkbox"]').forEach(cb => {
      if (cb.checked) {
        indices.add(parseInt(cb.dataset.findingIndex, 10));
      }
    });
    return indices;
  }

  function resolveWith(result) {
    document.removeEventListener('keydown', onKeyDown);
    hide();
    if (currentResolve) {
      currentResolve(result);
      currentResolve = null;
    }
  }

  function onKeyDown(e) {
    if (e.key === 'Escape') {
      resolveWith({ action: 'cancel', selectedIndices: new Set() });
    }
  }

  function hide() {
    if (overlayElement) {
      overlayElement.remove();
      overlayElement = null;
    }
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  return { show, hide };
})();

if (typeof window !== 'undefined') {
  window.SecurePromptModal = SecurePromptModal;
}
