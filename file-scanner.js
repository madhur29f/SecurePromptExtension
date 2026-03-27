/**
 * SecurePrompt — File Scanner
 * Extracts text from PDF, DOCX, CSV, JSON, TXT files and scans for PII.
 * Uses PDF.js for PDFs, JSZip for DOCX, Canvas API for image metadata.
 */

const FileScanner = (() => {
  let pdfLib = null;
  let jsZip = null;

  /**
   * Lazily load PDF.js library.
   */
  async function loadPDFLib() {
    if (pdfLib) return pdfLib;
    try {
      const workerUrl = chrome.runtime.getURL('libs/pdf.worker.min.mjs');
      const pdfUrl = chrome.runtime.getURL('libs/pdf.min.mjs');
      pdfLib = await import(pdfUrl);
      pdfLib.GlobalWorkerOptions.workerSrc = workerUrl;
      return pdfLib;
    } catch (e) {
      console.warn('[SecurePrompt] PDF.js not available:', e.message);
      return null;
    }
  }

  /**
   * Lazily load JSZip library.
   */
  async function loadJSZip() {
    if (jsZip) return jsZip;
    try {
      // JSZip is loaded as a content script, should be on window
      if (typeof window.JSZip !== 'undefined') {
        jsZip = window.JSZip;
        return jsZip;
      }
      return null;
    } catch (e) {
      console.warn('[SecurePrompt] JSZip not available:', e.message);
      return null;
    }
  }

  /**
   * Read a File as ArrayBuffer.
   */
  function readAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(file);
    });
  }

  /**
   * Read a File as text.
   */
  function readAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error);
      reader.readAsText(file);
    });
  }

  /**
   * Read a File as Data URL.
   */
  function readAsDataURL(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error);
      reader.readAsDataURL(file);
    });
  }

  /**
   * Extract text from a PDF file.
   */
  async function extractPDFText(file) {
    const lib = await loadPDFLib();
    if (!lib) {
      return { text: '', error: 'PDF.js library not available', partial: true };
    }

    try {
      const arrayBuffer = await readAsArrayBuffer(file);
      const pdf = await lib.getDocument({ data: arrayBuffer }).promise;
      const textParts = [];

      for (let i = 1; i <= pdf.numPages; i++) {
        const page = await pdf.getPage(i);
        const content = await page.getTextContent();
        const pageText = content.items.map(item => item.str).join(' ');
        textParts.push(pageText);
      }

      return { text: textParts.join('\n'), error: null, partial: false };
    } catch (e) {
      return { text: '', error: `PDF extraction failed: ${e.message}`, partial: true };
    }
  }

  /**
   * Extract text from a DOCX file.
   */
  async function extractDOCXText(file) {
    const JSZipLib = await loadJSZip();
    if (!JSZipLib) {
      // Fallback: try reading as text
      try {
        const text = await readAsText(file);
        return { text, error: null, partial: true };
      } catch (e) {
        return { text: '', error: 'JSZip library not available', partial: true };
      }
    }

    try {
      const arrayBuffer = await readAsArrayBuffer(file);
      const zip = await JSZipLib.loadAsync(arrayBuffer);
      const docXml = await zip.file('word/document.xml')?.async('text');

      if (!docXml) {
        return { text: '', error: 'No document.xml found in DOCX', partial: true };
      }

      // Parse XML and extract text
      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(docXml, 'application/xml');

      // Get all text nodes from <w:t> elements
      const textNodes = xmlDoc.getElementsByTagNameNS(
        'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
        't'
      );

      const texts = [];
      for (const node of textNodes) {
        texts.push(node.textContent);
      }

      return { text: texts.join(' '), error: null, partial: false };
    } catch (e) {
      return { text: '', error: `DOCX extraction failed: ${e.message}`, partial: true };
    }
  }

  async function performOCR(file) {
    try {
      const dataUrl = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });

      const response = await chrome.runtime.sendMessage({
        type: 'OCR_IMAGE',
        dataUrl
      });
      
      if (response && response.error) {
        console.warn('[SecurePrompt] Offscreen OCR failed:', response.error);
        return null;
      }
      return response; // { text, words: Array<{text, bbox: {x0,y0,x1,y1,width,height}}> }
    } catch (e) {
      console.warn('[SecurePrompt] OCR messaging failed:', e);
      return null;
    }
  }

  async function analyzeImage(file) {
    const findings = [];
    const warnings = [];
    let extractedText = '';
    let ocrData = null;

    // 1. Initial filename scan
    const nameFindings = window.PIIDetector ? window.PIIDetector.scan(file.name) : [];
    if (nameFindings.length > 0) {
      warnings.push({
        source: 'filename',
        message: `Filename "${file.name}" contains sensitive data.`,
        findings: nameFindings
      });
    }

    // 2. Offscreen OCR Preprocessing
    console.log(`[SecurePrompt OCR] Analyzing ${file.name}...`);
    ocrData = await performOCR(file);

    // 3. Multi-Layered Data Detection
    if (ocrData && ocrData.text) {
      extractedText = ocrData.text;
      const textFindings = window.PIIDetector ? window.PIIDetector.scan(extractedText) : [];
      if (textFindings.length > 0) {
         findings.push(...textFindings);
      }
    } else {
      warnings.push({
        source: 'visual',
        message: 'Image may contain visible sensitive information (IDs, screenshots). Please review before sending.',
        findings: []
      });
    }

    if (findings.length > 0) {
      warnings.push({
        source: 'visual',
        message: 'Sensitive text was detected inside this image. Tap "Redact & Send" to black it out.',
        findings: []
      });
    }

    return { text: extractedText, findings, warnings, ocrWords: ocrData ? ocrData.words : null };
  }

  /**
   * Scan a file for PII.
   * @param {File} file
   * @returns {Promise<{filename: string, type: string, findings: Array, warnings: Array, error: string|null}>}
   */
  async function scanFile(file) {
    const result = {
      filename: file.name,
      fileType: file.type,
      fileSize: file.size,
      findings: [],
      warnings: [],
      error: null
    };

    const ext = file.name.split('.').pop()?.toLowerCase();
    const mimeType = file.type.toLowerCase();

    try {
      // ── PDF ──
      if (ext === 'pdf' || mimeType === 'application/pdf') {
        const extracted = await extractPDFText(file);
        if (extracted.error) {
          result.warnings.push({ source: 'extraction', message: extracted.error, findings: [] });
        }
        if (extracted.text) {
          result.findings = window.PIIDetector ? window.PIIDetector.scan(extracted.text) : [];
        }
        if (extracted.partial) {
          result.warnings.push({
            source: 'partial',
            message: 'PDF text extraction may be incomplete. Review the document for additional sensitive content.',
            findings: []
          });
        }
      }
      // ── DOCX ──
      else if (ext === 'docx' || mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
        const extracted = await extractDOCXText(file);
        if (extracted.error) {
          result.warnings.push({ source: 'extraction', message: extracted.error, findings: [] });
        }
        if (extracted.text) {
          result.findings = window.PIIDetector ? window.PIIDetector.scan(extracted.text) : [];
        }
      }
      
      // ── Images ──
      else if (mimeType.startsWith('image/') || ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg'].includes(ext)) {
        const imageResult = await analyzeImage(file);
        result.warnings = imageResult.warnings;
        
        // Merge image findings
        if (imageResult.findings && imageResult.findings.length > 0) {
          result.findings.push(...imageResult.findings);
        }
        for (const w of imageResult.warnings) {
          if (w.findings && w.findings.length > 0) result.findings.push(...w.findings);
        }
        
        if (imageResult.ocrWords) result.ocrWords = imageResult.ocrWords;
      }
      
      // ── Text-based files ──
      else if (
        mimeType.startsWith('text/') ||
        ['txt', 'csv', 'json', 'xml', 'yaml', 'yml', 'md', 'log', 'sql', 'env', 'ini', 'conf', 'cfg', 'properties'].includes(ext) ||
        mimeType === 'application/json' ||
        mimeType === 'application/xml'
      ) {
        const text = await readAsText(file);
        result.findings = window.PIIDetector ? window.PIIDetector.scan(text) : [];
      }
      // ── Unknown files ──
      else {
        // Try reading as text anyway
        try {
          const text = await readAsText(file);
          if (text && text.length > 0 && !/[\x00-\x08\x0E-\x1F]/.test(text.slice(0, 1000))) {
            result.findings = window.PIIDetector ? window.PIIDetector.scan(text) : [];
          } else {
            result.warnings.push({
              source: 'unknown',
              message: `Binary file "${file.name}" cannot be scanned for text-based PII. Review before uploading.`,
              findings: []
            });
          }
        } catch (e) {
          result.warnings.push({
            source: 'unknown',
            message: `Could not read "${file.name}" for PII scanning.`,
            findings: []
          });
        }
      }
    } catch (e) {
      result.error = `Error scanning file: ${e.message}`;
    }

    return result;
  }

  /**
   * Scan multiple files.
   * @param {FileList|File[]} files
   * @returns {Promise<Array>}
   */
  async function scanFiles(files) {
    const results = [];
    for (const file of files) {
      results.push(await scanFile(file));
    }
    return results;
  }

  /**
   * Redact a file based on scan findings and selected indices.
   * @param {File} file 
   * @param {Object} result - The result object from scanFile
   * @param {Set<number>} selectedIndices - Indices of findings to redact
   * @returns {Promise<File|null>} A new File object, or null if no redaction possible
   */
  async function redactFile(file, result, selectedIndices) {
    if (!window.PIIDetector || !selectedIndices || selectedIndices.size === 0) return file;

    const ext = file.name.split('.').pop()?.toLowerCase();
    const mimeType = file.type.toLowerCase();

    try {
      // ── PDF ──
      // Instead of changing the file extension to .txt (which breaks ChatGPT's presigned uploads),
      // we use pdf-lib to generate a new valid PDF containing the redacted text.
      if (ext === 'pdf' || mimeType === 'application/pdf') {
        const extracted = await extractPDFText(file);
        if (!extracted.text) return file;
        const redactedText = window.PIIDetector.redact(extracted.text, result.findings, selectedIndices);
        
        if (window.PDFLib) {
          const pdfDoc = await window.PDFLib.PDFDocument.create();
          const font = await pdfDoc.embedFont(window.PDFLib.StandardFonts.Helvetica);
          
          // Basic pagination to prevent overflowing the page bottom
          const lines = redactedText.split('\n');
          let page = pdfDoc.addPage();
          let { width, height } = page.getSize();
          let y = height - 50;
          
          page.drawText('--- REDACTED SECURE COPY ---', { x: 50, y, size: 14, font });
          y -= 30;

          for (const line of lines) {
            // Chunk long lines roughly (approx 90 chars per line at size 11)
            const chunks = line.match(/.{1,90}/g) || [''];
            for (const chunk of chunks) {
              if (y < 50) {
                page = pdfDoc.addPage();
                y = height - 50;
              }
              page.drawText(chunk, { x: 50, y, size: 11, font });
              y -= 14;
            }
          }
          
          const pdfBytes = await pdfDoc.save();
          const newName = file.name.replace(/\.[^/.]+$/, "") + "_redacted.pdf";
          return new File([pdfBytes], newName, { type: 'application/pdf' });
        } else {
          // Fallback if pdf-lib didn't load
          const newName = file.name.replace(/\.[^/.]+$/, "") + "_redacted.txt";
          return new File([redactedText], newName, { type: 'text/plain' });
        }
      }
      
      // ── DOCX ──
      else if (ext === 'docx' || mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
        const extracted = await extractDOCXText(file);
        if (!extracted.text) return file;
        const redactedText = window.PIIDetector.redact(extracted.text, result.findings, selectedIndices);
        
        // Outputting a clean .txt file instead of trying to rebuild a fragile .docx archive
        // Since we hijack the upload at the DOM Event level, React gracefully accepts the .txt
        const newName = file.name.replace(/\.[^/.]+$/, "") + "_redacted.txt";
        return new File([redactedText], newName, { type: 'text/plain' });
      }
      
      // ── Images (Canvas Reconstruction & Pixel Destruction) ──
      else if (mimeType.startsWith('image/') || ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg'].includes(ext)) {
        if (!result.ocrWords || result.findings.length === 0) return file;
        
        const selectedFindings = result.findings.filter((_, i) => selectedIndices.has(i));
        const blocksToRedact = [];
        
        // 4. Spatial Coordinate Intersection
        for (const finding of selectedFindings) {
           const piiStr = finding.value.toLowerCase().replace(/[^a-z0-9]/g, '');
           if (!piiStr) continue;
           
           for (const word of result.ocrWords) {
             const wordStr = word.text.toLowerCase().replace(/[^a-z0-9]/g, '');
             if (!wordStr) continue;
             if (piiStr === wordStr || (wordStr.length > 2 && (piiStr.includes(wordStr) || wordStr.includes(piiStr)))) {
               // Pad the bounding box slightly to ensure full coverage
               blocksToRedact.push({
                 x: word.bbox.x0 - 2,
                 y: word.bbox.y0 - 2,
                 w: word.bbox.width + 4,
                 h: word.bbox.height + 4
               });
             }
           }
        }
        
        if (blocksToRedact.length === 0) return file;
        
        // 5. Canvas Reconstruction & 6. Reserialization
        return new Promise((resolve) => {
          const img = new Image();
          img.onload = () => {
             const canvas = document.createElement('canvas');
             canvas.width = img.width;
             canvas.height = img.height;
             const ctx = canvas.getContext('2d');
             
             // Paint original image
             ctx.drawImage(img, 0, 0);
             
             // Pixel Destruction
             ctx.fillStyle = '#1e1e1e'; // Dark gray as requested
             for (const block of blocksToRedact) {
               ctx.fillRect(block.x, block.y, block.w, block.h);
             }
             
             canvas.toBlob((blob) => {
               const newName = file.name.replace(/\.[^/.]+$/, "") + "_redacted.png";
               resolve(new File([blob], newName, { type: 'image/png' }));
             }, 'image/png');
          };
          img.onerror = () => resolve(file);
          img.src = URL.createObjectURL(file);
        });
      }
      
      
      // ── Text-based files ──
      else {
        try {
          const text = await readAsText(file);
          const redactedText = window.PIIDetector.redact(text, result.findings, selectedIndices);
          const newName = file.name.includes('.') ? file.name.replace(/\.[^/.]+$/, (match) => "_redacted" + match) : file.name + "_redacted";
          return new File([redactedText], newName, { type: file.type || 'text/plain' });
        } catch (e) {
          return file;
        }
      }
    } catch (e) {
      console.error('[SecurePrompt] Redaction failed:', e);
      return file;
    }
  }

  return { scanFile, scanFiles, redactFile };
})();

if (typeof window !== 'undefined') {
  window.FileScanner = FileScanner;
}
