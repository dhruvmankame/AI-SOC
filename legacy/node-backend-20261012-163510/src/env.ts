import { config } from 'dotenv';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

// Load the repo-root .env (gitignored — holds DATABASE_URL, GEMINI_API_KEY).
// Falls back to an agents/.env if one exists.
const here = dirname(fileURLToPath(import.meta.url));
const rootEnv = resolve(here, '../../.env');
const localEnv = resolve(here, '../.env');
config({ path: existsSync(localEnv) ? localEnv : rootEnv });

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing env var ${name} (set it in the gitignored .env)`);
  return v;
}

export const ENV = {
  databaseUrl: required('DATABASE_URL'),
  geminiApiKey: required('GEMINI_API_KEY'),
  geminiModel: process.env.GEMINI_MODEL ?? 'gemini-3.8-flash',
  // per-incident agent budget (blueprint §8 shared incident-state contract)
  maxSteps: Number(process.env.AGENT_MAX_STEPS ?? 18),
  maxTokens: Number(process.env.AGENT_MAX_TOKENS ?? 120000),
};
