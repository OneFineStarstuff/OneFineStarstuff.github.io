const fs = require('fs');
const path = 'rag-agentic-dashboard/server.js';
let content = fs.readFileSync(path, 'utf8');

// Replace all govern.*map.*measure.*manage occurrences with a safe pattern
// We use a non-greedy or atomic approach, but in JS simple keywords are best.
content = content.replace(/\/govern\.\*map\.\*measure\.\*manage\/i/g, "/govern/i"); // Simplest fix for signals array

// Fix the if statement again just in case
content = content.replace(/if \(\/govern\.\*map\.\*measure\.\*manage\/i\.test\(text\)\)/g,
  "if (['govern', 'map', 'measure', 'manage'].every(k => text.toLowerCase().includes(k)))");

// Look for other dangerous patterns like .* in regex
// /large.enterprise/i is okay (dot is single char)
// /risk\s*(management|assess|mitigat)/i is okay

fs.writeFileSync(path, content);
