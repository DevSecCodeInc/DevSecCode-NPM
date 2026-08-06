#!/usr/bin/env node
"use strict";

const { main } = require("../lib/cli");

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = Number.isInteger(code) ? code : 1;
  },
  (err) => {
    const message = err && err.message ? err.message : String(err);
    process.stderr.write(`devseccode: ${message}\n`);
    process.exitCode = 1;
  },
);
