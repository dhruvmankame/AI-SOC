import pg from 'pg';
import { ENV } from './env.js';

// One pooled connection to Supabase Postgres. The agents use the server-side
// DATABASE_URL (never shipped to the browser). All *investigation* queries are
// read-only SELECTs; only the agent-output tables (evidence, incident_timeline,
// agent_runs, incidents.summary) are written.
const host = (() => {
  try { return new URL(ENV.databaseUrl.replace('postgres://', 'http://')).hostname; }
  catch { return ''; }
})();
const isLocal = host === 'localhost' || host === '127.0.0.1';

export const pool = new pg.Pool({
  connectionString: ENV.databaseUrl,
  ssl: isLocal ? undefined : { rejectUnauthorized: false },
  max: 4,
});

export async function q<T = any>(text: string, params: any[] = []): Promise<T[]> {
  const res = await pool.query(text, params);
  return res.rows as T[];
}

export async function closeDb() {
  await pool.end();
}
