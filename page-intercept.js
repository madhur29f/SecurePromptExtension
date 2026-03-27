/**
 * SecurePrompt — Page Intercept Script (runs in MAIN world)
 *
 * This script runs in the page's own JS context (not the isolated
 * content-script world). It monkey-patches fetch and XMLHttpRequest
 * to pause file uploads, request a scan from the content script,
 * and resume/modify the upload based on the user's choice.
 */

(() => {
  'use strict';

  // State for pending requests awaiting content script decision
  const pendingRequests = new Map();

  // Listen for responses from content script
  window.addEventListener('message', (event) => {
    if (event.source !== window || !event.data || event.data.type !== 'SP_SCAN_RESPONSE') return;
    
    const { id, action, redactedFile } = event.data;
    const pending = pendingRequests.get(id);
    if (pending) {
      pendingRequests.delete(id);
      pending.resolve({ action, redactedFile });
    }
  });

  function generateId() {
    return Math.random().toString(36).substring(2, 15);
  }

  /**
   * Send file to content script and wait for user decision.
   */
  function requestScan(fileOrBlob, filename = null) {
    return new Promise((resolve) => {
      const id = generateId();
      pendingRequests.set(id, { resolve });
      
      try {
        window.postMessage({
          type: 'SP_REQUEST_SCAN',
          id,
          file: fileOrBlob,
          filename: fileOrBlob.name || filename || 'unknown',
          size: fileOrBlob.size,
          mimeType: fileOrBlob.type
        }, '*');
      } catch (e) {
        // If postMessage fails (e.g. File cannot be cloned in some old browsers), allow it
        pendingRequests.delete(id);
        resolve({ action: 'allow' });
      }
    });
  }

  // ── 1. Patch Fetch ──
  const originalFetch = window.fetch.bind(window);
  window.fetch = async function (...args) {
    try {
      const [resource, init] = args;
      const body = init?.body;

      if (body instanceof FormData) {
        let fileEntry = null;
        for (const [key, value] of body.entries()) {
          if (value instanceof File || (value instanceof Blob && value.size > 512)) {
            fileEntry = { key, value };
            break; // Stop at first file for simplicity
          }
        }

        if (fileEntry) {
          console.log(`[SecurePrompt] Intercepted fetch upload: ${fileEntry.value.name || 'blob'}`);
          const decision = await requestScan(fileEntry.value);
          
          if (decision.action === 'cancel') {
            console.log(`[SecurePrompt] Upload blocked by user.`);
            return new Promise((_, reject) => reject(new Error('SecurePrompt: Upload cancelled by user')));
          } else if (decision.action === 'redact' && decision.redactedFile) {
            console.log(`[SecurePrompt] Injecting redacted file into upload stream.`);
            // Reconstruct FormData with the redacted file
            const newFormData = new FormData();
            for (const [k, v] of body.entries()) {
              if (k === fileEntry.key && v === fileEntry.value) {
                const filename = decision.redactedFile.name || v.name || 'redacted_file';
                newFormData.append(k, decision.redactedFile, filename);
              } else {
                newFormData.append(k, v);
              }
            }
            args[1].body = newFormData;
            
            // Critical fix: If the original fetch had a hardcoded Content-Type header, 
            // it contains an old multipart boundary. We MUST delete it so the browser
            // generates a new matching boundary for the new FormData.
            if (args[1].headers) {
              const headers = new Headers(args[1].headers);
              headers.delete('Content-Type');
              headers.delete('content-type');
              const plainHeaders = {};
              for (const [k, v] of headers.entries()) {
                plainHeaders[k] = v;
              }
              args[1].headers = plainHeaders;
            }
          }
        }
      } else if (body instanceof File || (body instanceof Blob && body.size > 512)) {
        console.log(`[SecurePrompt] Intercepted raw fetch upload.`);
        const decision = await requestScan(body);
        
        if (decision.action === 'cancel') {
          return new Promise((_, reject) => reject(new Error('SecurePrompt: Upload cancelled by user')));
        } else if (decision.action === 'redact' && decision.redactedFile) {
          args[1].body = decision.redactedFile;
        }
      }
    } catch (e) {
      // Don't break the page if intercept fails
    }

    return originalFetch(...args);
  };

  // ── 2. Patch XMLHttpRequest ──
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.send = async function (body) {
    if (body instanceof FormData) {
      let fileEntry = null;
      for (const [key, value] of body.entries()) {
        if (value instanceof File || (value instanceof Blob && value.size > 512)) {
          fileEntry = { key, value };
          break;
        }
      }

      if (fileEntry) {
        console.log(`[SecurePrompt] Intercepted XHR upload: ${fileEntry.value.name || 'blob'}`);
        const decision = await requestScan(fileEntry.value);
        
        if (decision.action === 'cancel') {
          console.log(`[SecurePrompt] Upload blocked by user.`);
          // Emulate a network error or abort
          this.abort();
          return;
        } else if (decision.action === 'redact' && decision.redactedFile) {
          console.log(`[SecurePrompt] Injecting redacted file into XHR.`);
          const newFormData = new FormData();
          for (const [k, v] of body.entries()) {
            if (k === fileEntry.key && v === fileEntry.value) {
              const filename = decision.redactedFile.name || v.name || 'redacted_file';
              newFormData.append(k, decision.redactedFile, filename);
            } else {
              newFormData.append(k, v);
            }
          }
          return originalXHRSend.call(this, newFormData);
        }
      }
    } else if (body instanceof File || (body instanceof Blob && body.size > 512)) {
      console.log(`[SecurePrompt] Intercepted raw XHR upload.`);
      const decision = await requestScan(body);
      
      if (decision.action === 'cancel') {
        this.abort();
        return;
      } else if (decision.action === 'redact' && decision.redactedFile) {
        return originalXHRSend.call(this, decision.redactedFile);
      }
    }

    return originalXHRSend.call(this, body);
  };

  console.log('[SecurePrompt] Heavy page intercept active ✓ (pausing uploads for scan)');
})();
