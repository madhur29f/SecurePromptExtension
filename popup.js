/**
 * SecurePrompt — Popup Logic
 * Handles settings, stats display, and detection type configuration.
 */

document.addEventListener('DOMContentLoaded', async () => {
  // ── DOM refs ──
  const toggleEnabled = document.getElementById('toggle-enabled');
  const toggleAutoRedact = document.getElementById('toggle-autoredact');
  const statusBar = document.getElementById('status-bar');
  const statusDot = document.getElementById('status-dot');
  const statusText = document.getElementById('status-text');
  const statDetected = document.getElementById('stat-detected');
  const statRedacted = document.getElementById('stat-redacted');
  const statBlocked = document.getElementById('stat-blocked');
  const statTotal = document.getElementById('stat-total');
  const typesGrid = document.getElementById('types-grid');
  const btnReset = document.getElementById('btn-reset');

  // ── Load settings ──
  let settings;
  try {
    settings = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
  } catch (e) {
    settings = {};
  }

  // Apply settings to UI
  toggleEnabled.checked = settings.enabled !== false;
  toggleAutoRedact.checked = settings.autoRedact || false;
  updateStatusUI(toggleEnabled.checked);

  // ── Load stats ──
  async function loadStats() {
    try {
      const { stats = {} } = await chrome.runtime.sendMessage({ type: 'GET_STATS' });
      statDetected.textContent = stats.todayDetected || 0;
      statRedacted.textContent = stats.totalRedacted || 0;
      statBlocked.textContent = stats.totalBlocked || 0;
      statTotal.textContent = stats.totalDetected || 0;
    } catch (e) {
      // Defaults are 0
    }
  }
  await loadStats();

  // ── Populate detection types ──
  const allTypes = PIIDetector.getTypes();
  const enabledTypes = settings.enabledTypes || null; // null = all

  allTypes.forEach(t => {
    const chip = document.createElement('div');
    chip.className = 'type-chip' + (enabledTypes === null || enabledTypes.includes(t.type) ? ' active' : '');
    chip.dataset.type = t.type;
    chip.innerHTML = `<span class="chip-icon">${t.icon}</span><span>${t.label}</span>`;
    chip.addEventListener('click', () => {
      chip.classList.toggle('active');
      saveTypeSettings();
    });
    typesGrid.appendChild(chip);
  });

  // ── Event handlers ──
  toggleEnabled.addEventListener('change', async () => {
    const enabled = toggleEnabled.checked;
    updateStatusUI(enabled);
    await chrome.runtime.sendMessage({
      type: 'UPDATE_SETTINGS',
      settings: { enabled }
    });
  });

  toggleAutoRedact.addEventListener('change', async () => {
    await chrome.runtime.sendMessage({
      type: 'UPDATE_SETTINGS',
      settings: { autoRedact: toggleAutoRedact.checked }
    });
  });

  btnReset.addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ type: 'RESET_STATS' });
    await loadStats();
    // Flash animation
    btnReset.textContent = 'Cleared ✓';
    setTimeout(() => { btnReset.textContent = 'Reset Stats'; }, 1200);
  });

  // ── Helpers ──
  function updateStatusUI(enabled) {
    if (enabled) {
      statusBar.classList.remove('disabled');
      statusDot.className = 'status-dot active';
      statusText.textContent = 'Protecting your data';
    } else {
      statusBar.classList.add('disabled');
      statusDot.className = 'status-dot inactive';
      statusText.textContent = 'Protection disabled';
    }
  }

  async function saveTypeSettings() {
    const activeChips = typesGrid.querySelectorAll('.type-chip.active');
    const total = typesGrid.querySelectorAll('.type-chip').length;

    let enabledTypes;
    if (activeChips.length === total) {
      enabledTypes = null; // All enabled
    } else {
      enabledTypes = Array.from(activeChips).map(c => c.dataset.type);
    }

    await chrome.runtime.sendMessage({
      type: 'UPDATE_SETTINGS',
      settings: { enabledTypes }
    });
  }
});
