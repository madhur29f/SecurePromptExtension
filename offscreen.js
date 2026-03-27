/**
 * SecurePrompt — Offscreen Document Script
 * Runs Tesseract.js OCR completely offline within the extension's sandbox.
 */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'OCR_IMAGE' && message.target === 'offscreen') {
    handleOCR(message.dataUrl).then(sendResponse);
    return true; // Keep message channel open for async response
  }
});

async function handleOCR(dataUrl) {
  try {
    // We configure Tesseract to use our local bundled worker and webassembly files
    // so no external requests are made.
    const worker = await Tesseract.createWorker('eng', 1, {
      workerPath: chrome.runtime.getURL('libs/tesseract/worker.min.js'),
      corePath: chrome.runtime.getURL('libs/tesseract/tesseract-core.wasm.js'),
      langPath: chrome.runtime.getURL('libs/tesseract'),
      workerBlobURL: false,
      logger: m => console.log(`[SecurePrompt OCR] ${m.status}: ${(m.progress * 100).toFixed(0)}%`)
    });
    
    // Run OCR detection
    const { data } = await worker.recognize(dataUrl);
    
    // Map output to text and geometric bounding boxes (X, Y, Width, Height)
    const words = data.words.map(w => ({
      text: w.text,
      bbox: {
        x0: w.bbox.x0,
        y0: w.bbox.y0,
        x1: w.bbox.x1,
        y1: w.bbox.y1,
        width: w.bbox.x1 - w.bbox.x0,
        height: w.bbox.y1 - w.bbox.y0
      }
    }));
    
    await worker.terminate();
    
    return {
      text: data.text,
      words: words
    };
  } catch (e) {
    console.error('[SecurePrompt OCR Worker Error]', e);
    return { error: e.toString() };
  }
}
