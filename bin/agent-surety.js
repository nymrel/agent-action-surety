#!/usr/bin/env node
/**
 * Agent Action Surety - Node CLI Executable
 * Zero-dependency execution firewall & policy envelope.
 * Copyright (c) 2026 Nymrel / JalenBuilds LLC.
 */

import * as path from 'node:path';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function bootstrap() {
  // Check if dist exists, else import src directly
  const distCli = path.join(__dirname, '..', 'dist', 'cli.js');
  const srcCli = path.join(__dirname, '..', 'src', 'cli.js');

  let cliModule: any;
  if (fs.existsSync(distCli)) {
    cliModule = await import(distCli);
  } else if (fs.existsSync(srcCli)) {
    cliModule = await import(srcCli);
  } else {
    // If running in raw ts development mode
    try {
      cliModule = await import('../src/cli.js');
    } catch {
      console.error('Error: agent-surety build artifacts not found. Run "npm run build" first.');
      process.exit(1);
    }
  }

  const exitCode = await cliModule.runCli(process.argv.slice(2));
  process.exit(exitCode);
}

bootstrap().catch((err) => {
  console.error('Fatal CLI Error:', err);
  process.exit(1);
});
