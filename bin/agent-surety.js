#!/usr/bin/env node
/**
 * Agent Action Surety - Node CLI Executable
 * Zero-dependency execution firewall & policy envelope.
 * Copyright (c) 2026 Nymrel / JalenBuilds LLC.
 */

import * as path from 'node:path';
import * as fs from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function bootstrap() {
  const distCli = path.join(__dirname, '..', 'dist', 'cli.js');

  if (!fs.existsSync(distCli)) {
    console.error('Error: agent-surety build artifacts not found. Run "npm run build" first.');
    process.exitCode = 1;
    return;
  }

  const cliModule = await import(pathToFileURL(distCli).href);
  const exitCode = await cliModule.runCli(process.argv.slice(2));
  process.exitCode = exitCode;
}

bootstrap().catch((error) => {
  console.error('Fatal CLI Error:', error);
  process.exitCode = 1;
});
