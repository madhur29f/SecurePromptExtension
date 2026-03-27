/**
 * SecurePrompt — PII Detection Engine
 * Pure regex-based detector for sensitive data patterns.
 * Runs entirely on-device, no network calls.
 */

const PIIDetector = (() => {
  // ── Luhn algorithm for credit card validation ──
  function luhnCheck(num) {
    const digits = num.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0;
    let alternate = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let n = parseInt(digits[i], 10);
      if (alternate) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      alternate = !alternate;
    }
    return sum % 10 === 0;
  }

  // ── Pattern definitions ──
  const patterns = [
    {
      type: 'CREDIT_CARD',
      label: 'Credit Card Number',
      icon: '💳',
      regex: /\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{1,2}[-\s]?[0-9]{4,6}[-\s]?[0-9]{5}|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b/g,
      validate: (match) => luhnCheck(match)
    },
    {
      type: 'SSN',
      label: 'Social Security Number',
      icon: '🆔',
      regex: /\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b/g,
      validate: null
    },
    {
      type: 'EMAIL',
      label: 'Email Address',
      icon: '📧',
      regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
      validate: null
    },
    {
      type: 'PHONE',
      label: 'Phone Number',
      icon: '📱',
      regex: /(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
      validate: (match) => match.replace(/\D/g, '').length >= 10
    },
    {
      type: 'PHONE_INTL',
      label: 'International Phone',
      icon: '📱',
      regex: /\+(?:[1-9]\d{0,2})[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}[-.\s]?\d{0,4}\b/g,
      validate: (match) => match.replace(/\D/g, '').length >= 10
    },
    {
      type: 'AWS_KEY',
      label: 'AWS Access Key',
      icon: '🔑',
      regex: /\b(AKIA|ABIA|ACCA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
      validate: null
    },
    {
      type: 'AWS_SECRET',
      label: 'AWS Secret Key',
      icon: '🔑',
      regex: /(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*[\"\']?[A-Za-z0-9/+=]{40}[\"\']?/gi,
      validate: null
    },
    {
      type: 'GITHUB_TOKEN',
      label: 'GitHub Token',
      icon: '🔑',
      regex: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g,
      validate: null
    },
    {
      type: 'GOOGLE_API_KEY',
      label: 'Google API Key',
      icon: '🔑',
      regex: /\bAIza[A-Za-z0-9_\-]{35}\b/g,
      validate: null
    },
    {
      type: 'STRIPE_KEY',
      label: 'Stripe API Key',
      icon: '🔑',
      regex: /\b[sr]k_(live|test)_[A-Za-z0-9]{20,}\b/g,
      validate: null
    },
    {
      type: 'GENERIC_API_KEY',
      label: 'API Key / Secret',
      icon: '🔑',
      regex: /(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key|private[_-]?key|client[_-]?secret)\s*[=:]\s*[\"\']?[A-Za-z0-9_\-./+=]{16,}[\"\']?/gi,
      validate: null
    },
    {
      type: 'PASSWORD',
      label: 'Password / Secret',
      icon: '🔒',
      regex: /(?:password|passwd|pwd|secret|token)\s*[=:]\s*[\"\']?[^\s\"\']{6,}[\"\']?/gi,
      validate: null
    },
    {
      type: 'PRIVATE_KEY',
      label: 'Private Key',
      icon: '🔐',
      regex: /-----BEGIN\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s|PGP\s)?PRIVATE\sKEY(?:\sBLOCK)?-----[\s\S]*?-----END\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s|PGP\s)?PRIVATE\sKEY(?:\sBLOCK)?-----/g,
      validate: null
    },
    {
      type: 'JWT',
      label: 'JWT Token',
      icon: '🎟️',
      regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
      validate: null
    },
    {
      type: 'AADHAAR',
      label: 'Aadhaar Number',
      icon: '🆔',
      regex: /\b[2-9]\d{3}[-\s]?\d{4}[-\s]?\d{4}\b/g,
      validate: (match) => match.replace(/\D/g, '').length === 12
    },
    {
      type: 'PAN_CARD',
      label: 'PAN Card',
      icon: '🆔',
      regex: /\b[A-Z]{5}\d{4}[A-Z]\b/g,
      validate: null
    },
    {
      type: 'IPV4',
      label: 'IP Address',
      icon: '🌐',
      regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g,
      validate: (match) => {
        // Exclude common non-sensitive IPs
        const exclude = ['0.0.0.0', '127.0.0.1', '255.255.255.255', '192.168.0.1', '10.0.0.1'];
        return !exclude.includes(match);
      }
    },
    {
      type: 'CONNECTION_STRING',
      label: 'Database Connection String',
      icon: '🗄️',
      regex: /(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|mssql):\/\/[^\s\"\']+/gi,
      validate: null
    },
    {
      type: 'BEARER_TOKEN',
      label: 'Bearer Token',
      icon: '🎟️',
      regex: /Bearer\s+[A-Za-z0-9_\-./+=]{20,}/g,
      validate: null
    },
    {
      type: 'NAME',
      label: 'Person Name',
      icon: '👤',
      regex: /(?:\b(?:Aarav|Aarti|Aditya|Ajay|Akash|Akhil|Amit|Anand|Anil|Anjali|Ankit|Anup|Arjun|Arvind|Asha|Ashish|Ashok|Avinash|Bharat|Bhavna|Chetan|Deepa|Deepali|Deepak|Dev|Dinesh|Divya|Ganesh|Gaurav|Gita|Gopal|Hari|Hemant|Isha|Jagdish|Jay|Jyoti|Kailash|Kamal|Kamesh|Karan|Kavita|Kavya|Kiran|Kishore|Krishna|Kulkarni|Kumar|Kunal|Lakshmi|Lalit|Lata|Madhu|Madhuri|Mahesh|Mamta|Manish|Manju|Manoj|Mayank|Meena|Megha|Mohan|Mohini|Mohit|Mukesh|Mukund|Namrata|Nandini|Naveen|Neelam|Neha|Nidhi|Nikhil|Nisha|Nishant|Nitin|Om|Omkar|Pallavi|Pankaj|Parth|Patel|Pavan|Pooja|Poonam|Pradeep|Prajakta|Prakash|Pramod|Pranab|Prasad|Prashant|Pratik|Praveen|Prem|Priya|Priyanka|Puneet|Radha|Raghu|Rahul|Raj|Rajan|Rajendra|Rajesh|Rajiv|Raju|Rakesh|Ram|Raman|Ramesh|Ravi|Reena|Rekha|Ritu|Rohan|Rohit|Roshan|Rupal|Rupesh|Sachin|Sameer|Sandhya|Sangeeta|Sanjay|Sanjeev|Santosh|Sarita|Satish|Saurabh|Savita|Seema|Shailendra|Shalini|Shankar|Sharad|Sharma|Shashank|Shikha|Shilpa|Shiv|Shruti|Shubham|Siddharth|Singh|Smriti|Sneha|Sonal|Subhash|Sudhir|Sujata|Sujit|Suman|Sumit|Sunil|Sunitha|Suraj|Suresh|Surya|Sushant|Sushma|Swara|Swati|Tarun|Tejas|Trisha|Uday|Umesh|Upendra|Usha|Vaibhav|Varun|Vasudev|Ved|Vidya|Vijay|Vikas|Vikram|Vimal|Vinay|Vinita|Vinod|Vipin|Vishal|Vishnu|Vivek|Yash|Yogesh)\s+[A-Z][a-z]+\b|\b[A-Z][a-z]+\s+(?:Agarwal|Ahuja|Bansal|Bhat|Bhatt|Bose|Chakraborty|Chatterjee|Chauhan|Chopra|Das|Desai|Deshmukh|Dixit|Dubey|Garg|Ghosh|Goyal|Gupta|Iyer|Jain|Jha|Joshi|Kapoor|Kaur|Khan|Khatri|Kulkarni|Kumar|Mehra|Mishra|Mukherjee|Nair|Pandey|Patel|Patil|Pillai|Prakash|Prasad|Rajput|Rao|Rathore|Reddy|Roy|Saini|Saxena|Sen|Seth|Shah|Sharma|Shetty|Shukla|Singh|Sinha|Soni|Srivastava|Srinivas|Thakur|Tiwari|Varma|Verma|Yadav)\b|(?:Mr\.|Mrs\.|Ms\.|Miss|Shri|Smt\.|Dr\.|Name:?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b)/g,
      validate: null
    },
    {
      type: 'DATE_OF_BIRTH',
      label: 'Date of Birth',
      icon: '📅',
      regex: /\b(?:(?:0?[1-9]|[12]\d|3[01])[-\/.\s](?:0?[1-9]|1[0-2]|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[-\/.\s](?:19|20)\d{2}|(?:19|20)\d{2}[-\/.\s](?:0?[1-9]|1[0-2]|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[-\/.\s](?:0?[1-9]|[12]\d|3[01]))\b/gi,
      validate: (match) => {
        const yearMatch = match.match(/(?:19|20)\d{2}/);
        if (yearMatch) {
          const year = parseInt(yearMatch[0], 10);
          return year >= 1900 && year <= new Date().getFullYear() + 5;
        }
        return false;
      }
    }
  ];

  /**
   * Scan text for PII matches.
   * @param {string} text - The text to scan.
   * @param {string[]} [enabledTypes] - Optional array of types to scan for. If null, scan all.
   * @returns {Array<{type: string, label: string, icon: string, value: string, start: number, end: number, masked: string}>}
   */
  function scan(text, enabledTypes = null) {
    if (!text || typeof text !== 'string' || text.trim().length === 0) return [];

    const findings = [];
    const usedRanges = [];

    for (const pattern of patterns) {
      if (enabledTypes && !enabledTypes.includes(pattern.type)) continue;

      // Reset regex lastIndex
      pattern.regex.lastIndex = 0;
      let match;

      while ((match = pattern.regex.exec(text)) !== null) {
        const value = match[0];
        const start = match.index;
        const end = start + value.length;

        // Validate if validator exists
        if (pattern.validate && !pattern.validate(value)) continue;

        // Check overlap with existing findings (prefer earlier/longer match)
        const overlaps = usedRanges.some(
          (r) => start < r.end && end > r.start
        );
        if (overlaps) continue;

        usedRanges.push({ start, end });

        findings.push({
          type: pattern.type,
          label: pattern.label,
          icon: pattern.icon,
          value: value,
          start: start,
          end: end,
          masked: maskValue(value, pattern.type)
        });
      }
    }

    // Sort by position
    findings.sort((a, b) => a.start - b.start);
    return findings;
  }

  /**
   * Mask a detected value for display.
   */
  function maskValue(value, type) {
    switch (type) {
      case 'CREDIT_CARD':
        return value.replace(/\d(?=\d{4})/g, '•');
      case 'SSN':
        return '•••-••-' + value.slice(-4);
      case 'EMAIL': {
        const [local, domain] = value.split('@');
        return local[0] + '•'.repeat(Math.max(local.length - 2, 1)) + local.slice(-1) + '@' + domain;
      }
      case 'PHONE':
      case 'PHONE_INTL':
        return value.slice(0, 3) + '•'.repeat(value.length - 5) + value.slice(-2);
      case 'AADHAAR':
        return '••••-••••-' + value.slice(-4);
      case 'PAN_CARD':
        return value.slice(0, 2) + '•••••' + value.slice(-2);
      case 'PASSWORD':
      case 'AWS_SECRET':
      case 'GENERIC_API_KEY':
        // Show prefix, mask value
        const eqIdx = value.search(/[=:]/);
        if (eqIdx > -1) {
          return value.slice(0, eqIdx + 1) + ' ••••••••';
        }
        return '••••••••';
      case 'NAME':
        return value.replace(/[a-z]/g, '•');
      case 'DATE_OF_BIRTH':
        return value.replace(/\d/g, 'x');
      default:
        if (value.length <= 8) return '•'.repeat(value.length);
        return value.slice(0, 4) + '•'.repeat(Math.min(value.length - 8, 20)) + value.slice(-4);
    }
  }

  /**
   * Redact all findings in text.
   * @param {string} text
   * @param {Array} findings - Array of finding objects from scan()
   * @param {Set} [selectedIndices] - Indices of findings to redact. If null, redact all.
   * @returns {string}
   */
  function redact(text, findings, selectedIndices = null) {
    if (!findings || findings.length === 0) return text;

    // Process from end to start to preserve indices
    const sorted = [...findings].sort((a, b) => b.start - a.start);
    let result = text;

    sorted.forEach((finding, i) => {
      const originalIdx = findings.indexOf(finding);
      if (selectedIndices && !selectedIndices.has(originalIdx)) return;
      const placeholder = `[REDACTED:${finding.type}]`;
      result = result.slice(0, finding.start) + placeholder + result.slice(finding.end);
    });

    return result;
  }

  /**
   * Get all supported PII types.
   */
  function getTypes() {
    return patterns.map(p => ({
      type: p.type,
      label: p.label,
      icon: p.icon
    }));
  }

  return { scan, redact, getTypes, maskValue };
})();

// Make available globally for content scripts
if (typeof window !== 'undefined') {
  window.PIIDetector = PIIDetector;
}
