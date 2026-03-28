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
        const pageText = content.items.map(item => item.str + (item.hasEOL ? '\n' : ' ')).join('').replace(/ \n/g, '\n');
        textParts.push(pageText);
      }

      return { text: textParts.join('\n'), error: null, partial: false };
    } catch (e) {
      return { text: '', error: `PDF extraction failed: ${e.message}`, partial: true };
    }
  }

  /**
   * Extract and analyze PDF metadata for sensitive corporate information.
   * Detects: Author, Company, Classification tags (Confidential, Private, etc.)
   */
  async function extractPDFMetadata(file) {
    const metadataFindings = [];
    const metadataFields = {};

    try {
      // Use pdf-lib to read metadata (it can parse existing PDFs)
      if (!window.PDFLib) {
        return { findings: [], fields: {}, error: 'pdf-lib not available' };
      }

      const arrayBuffer = await readAsArrayBuffer(file);
      const pdfDoc = await window.PDFLib.PDFDocument.load(arrayBuffer, {
        updateMetadata: false
      });

      // Read standard metadata fields
      metadataFields.title = pdfDoc.getTitle() || '';
      metadataFields.author = pdfDoc.getAuthor() || '';
      metadataFields.subject = pdfDoc.getSubject() || '';
      metadataFields.keywords = (pdfDoc.getKeywords() || '');
      metadataFields.creator = pdfDoc.getCreator() || '';
      metadataFields.producer = pdfDoc.getProducer() || '';

      // Corporate classification keywords to detect
      const classificationKeywords = [
        'confidential', 'private', 'internal', 'restricted', 'secret',
        'top secret', 'classified', 'sensitive', 'proprietary',
        'not for distribution', 'do not share', 'internal only',
        'company confidential', 'trade secret', 'privileged',
        'under nda', 'nda', 'for internal use only', 'draft',
        'strictly confidential', 'protected', 'controlled'
      ];

      // Check each metadata field
      const fieldsToCheck = [
        { key: 'title', label: 'Document Title', value: metadataFields.title },
        { key: 'author', label: 'Author Name', value: metadataFields.author },
        { key: 'subject', label: 'Subject', value: metadataFields.subject },
        { key: 'keywords', label: 'Keywords', value: metadataFields.keywords },
        { key: 'creator', label: 'Creator Software', value: metadataFields.creator },
        { key: 'producer', label: 'Producer', value: metadataFields.producer }
      ];

      for (const field of fieldsToCheck) {
        if (!field.value || field.value.trim() === '') continue;

        const lowerVal = field.value.toLowerCase();

        // Check for classification keywords
        for (const keyword of classificationKeywords) {
          if (lowerVal.includes(keyword)) {
            metadataFindings.push({
              type: 'PDF_CLASSIFICATION',
              label: `Corporate Classification (${field.label})`,
              icon: '🏢',
              severity: 1.0,
              value: `${field.label}: "${field.value}" [contains: ${keyword.toUpperCase()}]`,
              masked: `${field.label}: ●●●●● [${keyword.toUpperCase()}]`,
              metaKey: field.key
            });
            break; // One finding per field is enough
          }
        }

        // Flag non-empty Author/Title/Subject as identity-leaking metadata
        if (['author', 'title', 'subject'].includes(field.key)) {
          // Skip if already flagged as classification
          const alreadyFlagged = metadataFindings.some(f => f.metaKey === field.key);
          if (!alreadyFlagged && field.value.trim().length > 0) {
            metadataFindings.push({
              type: 'PDF_METADATA',
              label: `PDF Metadata (${field.label})`,
              icon: '📋',
              severity: 0.4,
              value: `${field.label}: "${field.value}"`,
              masked: `${field.label}: ●●●●●●●●`,
              metaKey: field.key
            });
          }
        }

        // Also scan metadata values for PII (email in author, etc.)
        if (window.PIIDetector) {
          const piiInMeta = window.PIIDetector.scan(field.value);
          for (const pii of piiInMeta) {
            metadataFindings.push({
              ...pii,
              label: `${pii.label} (in ${field.label})`,
              metaKey: field.key
            });
          }
        }
      }

      return { findings: metadataFindings, fields: metadataFields, error: null };
    } catch (e) {
      console.warn('[SecurePrompt] PDF metadata extraction failed:', e);
      return { findings: [], fields: metadataFields, error: e.message };
    }
  }

  /**
   * Strip all metadata from a PDF using pdf-lib.
   */
  async function stripPDFMetadata(pdfDoc) {
    try {
      pdfDoc.setTitle('');
      pdfDoc.setAuthor('');
      pdfDoc.setSubject('');
      pdfDoc.setKeywords([]);
      pdfDoc.setCreator('SecurePrompt');
      pdfDoc.setProducer('SecurePrompt — Metadata Stripped');
    } catch (e) {
      console.warn('[SecurePrompt] Metadata stripping partial failure:', e);
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

      // Extract text by Paragraphs (<w:p>) to preserve structure
      const pNodes = xmlDoc.getElementsByTagNameNS(
        'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
        'p'
      );

      const texts = [];
      for (const p of pNodes) {
        let pText = '';
        const tNodes = p.getElementsByTagNameNS(
          'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
          't'
        );
        for (const t of tNodes) {
          pText += t.textContent;
        }
        if (pText.trim()) texts.push(pText);
      }

      return { text: texts.join('\n'), error: null, partial: false };
    } catch (e) {
      return { text: '', error: `DOCX extraction failed: ${e.message}`, partial: true };
    }
  }

  /**
   * Extract text from an Excel (.xlsx) file.
   */
  async function extractXLSXText(file) {
    const JSZipLib = await loadJSZip();
    if (!JSZipLib) {
      return { text: '', error: 'JSZip library not available for Excel parsing', partial: true };
    }

    try {
      const arrayBuffer = await readAsArrayBuffer(file);
      const zip = await JSZipLib.loadAsync(arrayBuffer);
      const texts = [];

      // 1. Extract shared strings (most cell values live here)
      const sharedStringsXml = await zip.file('xl/sharedStrings.xml')?.async('text');
      const sharedStrings = [];
      if (sharedStringsXml) {
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(sharedStringsXml, 'application/xml');
        const siNodes = xmlDoc.getElementsByTagName('si');
        for (const si of siNodes) {
          const tNodes = si.getElementsByTagName('t');
          let cellText = '';
          for (const t of tNodes) {
            cellText += t.textContent;
          }
          sharedStrings.push(cellText);
          if (cellText.trim()) texts.push(cellText);
        }
      }

      // 2. Parse each worksheet for inline strings and numeric values
      const sheetFiles = Object.keys(zip.files).filter(f =>
        f.match(/^xl\/worksheets\/sheet\d+\.xml$/)
      );

      for (const sheetPath of sheetFiles) {
        const sheetXml = await zip.file(sheetPath)?.async('text');
        if (!sheetXml) continue;

        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(sheetXml, 'application/xml');
        const rows = xmlDoc.getElementsByTagName('row');

        for (const row of rows) {
          const cells = row.getElementsByTagName('c');
          const rowTexts = [];
          for (const cell of cells) {
            const type = cell.getAttribute('t');
            const vNode = cell.getElementsByTagName('v')[0];
            if (!vNode) continue;

            if (type === 's') {
              // Shared string reference — already captured above
              const idx = parseInt(vNode.textContent, 10);
              if (sharedStrings[idx]) rowTexts.push(sharedStrings[idx]);
            } else if (type === 'inlineStr') {
              // Inline string
              const tNode = cell.getElementsByTagName('t')[0];
              if (tNode) rowTexts.push(tNode.textContent);
            } else {
              // Number or other — include as-is (could be phone, Aadhaar digits)
              rowTexts.push(vNode.textContent);
            }
          }
          if (rowTexts.length > 0) texts.push(rowTexts.join(' | '));
        }
      }

      return { text: texts.join('\n'), error: null, partial: false };
    } catch (e) {
      return { text: '', error: `Excel extraction failed: ${e.message}`, partial: true };
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

  /**
   * Run offline face detection using tracking.js
   */
  async function detectFaces(file) {
    if (typeof tracking === 'undefined') {
      console.warn('[SecurePrompt] tracking.js missing.');
      return [];
    }
    return new Promise((resolve) => {
      const img = new Image();
      img.onload = () => {
        try {
          const tracker = new tracking.ObjectTracker('face');
          tracker.setStepSize(1.7);

          tracking.track(img, tracker);

          tracker.on('track', function (event) {
            resolve(event.data); // Array of {x, y, width, height}
          });

          // Fallback if no events fire within 2.5s
          setTimeout(() => resolve([]), 2500);
        } catch (e) {
          console.warn('[SecurePrompt] Face tracking error', e);
          resolve([]);
        }
      };
      img.onerror = () => resolve([]);
      img.src = URL.createObjectURL(file);
    });
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

    // 2b. Offline Face Detection
    const faces = await detectFaces(file);
    if (faces && faces.length > 0) {
      warnings.push({
        source: 'visual',
        message: `${faces.length} face(s) detected. Tap "Redact & Send" to mask them over box boundaries.`,
        findings: []
      });
      faces.forEach((f, i) => {
        findings.push({
          type: 'FACE',
          label: 'Detected Face',
          icon: '👤',
          value: `[Face Detection ${i + 1}]`,
          bbox: f
        });
      });
    }

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

        // ── Metadata Scan ──
        const metaResult = await extractPDFMetadata(file);
        if (metaResult.findings.length > 0) {
          result.findings.push(...metaResult.findings);

          // Check for corporate classification tags specifically
          const classificationFindings = metaResult.findings.filter(f => f.type === 'PDF_CLASSIFICATION');
          if (classificationFindings.length > 0) {
            const tags = classificationFindings.map(f => f.value).join(', ');
            result.warnings.push({
              source: 'metadata',
              message: `⚠️ CORPORATE CLASSIFIED DOCUMENT — This PDF contains classification tags in its metadata: ${tags}. Uploading this to an AI chatbot may violate your organization's data policy.`,
              findings: classificationFindings
            });
          }

          // General metadata warning
          const metaFields = metaResult.findings.filter(f => f.type === 'PDF_METADATA');
          if (metaFields.length > 0) {
            result.warnings.push({
              source: 'metadata',
              message: `PDF contains hidden metadata (Author, Title, Subject) that may reveal your identity or organization. Tap "Redact & Send" to strip it.`,
              findings: []
            });
          }
        }
        // Store metadata fields for use during redaction
        result._pdfMetaFields = metaResult.fields;
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
      // ── Excel (.xlsx) ──
      else if (ext === 'xlsx' || mimeType === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet') {
        const extracted = await extractXLSXText(file);
        if (extracted.error) {
          result.warnings.push({ source: 'extraction', message: extracted.error, findings: [] });
        }
        if (extracted.text) {
          result.findings = window.PIIDetector ? window.PIIDetector.scan(extracted.text) : [];
        }
        if (extracted.partial) {
          result.warnings.push({
            source: 'partial',
            message: 'Excel text extraction may be incomplete. Review the spreadsheet for additional sensitive content.',
            findings: []
          });
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

        // Filter out metadata-only findings for text redaction
        const textFindings = result.findings.filter(f => f.type !== 'PDF_METADATA' && f.type !== 'PDF_CLASSIFICATION');
        const redactedText = window.PIIDetector.redact(extracted.text, textFindings, selectedIndices);

        if (window.PDFLib) {
          const pdfDoc = await window.PDFLib.PDFDocument.create();
          const font = await pdfDoc.embedFont(window.PDFLib.StandardFonts.Helvetica);

          // ── STRIP ALL METADATA ──
          await stripPDFMetadata(pdfDoc);

          // Basic pagination to prevent overflowing the page bottom
          const lines = redactedText.split('\n');
          let page = pdfDoc.addPage();
          let { width, height } = page.getSize();
          let y = height - 50;

          page.drawText('--- REDACTED SECURE COPY (Metadata Stripped) ---', { x: 50, y, size: 14, font });
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

      // ── Excel (.xlsx) ──
      else if (ext === 'xlsx' || mimeType === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet') {
        const extracted = await extractXLSXText(file);
        if (!extracted.text) return file;
        const redactedText = window.PIIDetector.redact(extracted.text, result.findings, selectedIndices);

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
          if (finding.type === 'FACE' && finding.bbox) {
            blocksToRedact.push({
              x: finding.bbox.x - 5,
              y: finding.bbox.y - 15, // slightly raise to cover forehead
              w: finding.bbox.width + 10,
              h: finding.bbox.height + 25 // extend to cover jaw
            });
            continue;
          }

          if (!finding.value) continue;
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
