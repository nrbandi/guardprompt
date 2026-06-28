// PromptKavach – detector.js
//
// This file is a thin Node.js re-export of kavach-core for use in:
//   - The test suite (node kavach-core.test.js)
//   - Any future Node.js tooling (CLI scanner, API server, proxy)
//
// It is NOT loaded by Chrome. The browser gets kavach-core.js directly
// via manifest.json content_scripts, where it sets window.KavachCore.
//
// To use in Node.js:
//   const { detect, redact, getRules } = require('./src/detector');

"use strict";

module.exports = require("./kavach-core");
