import { createClient } from '@supabase/supabase-js'

const url = import.meta.env.VITE_SUPABASE_URL as string
const key = import.meta.env.VITE_SUPABASE_ANON_KEY as string

if (!url || !key) {
  // Fail loud in dev rather than making silent, empty queries.
  throw new Error(
    'Missing VITE_SUPABASE_URL / VITE_SUPABASE_ANON_KEY. Copy web/.env.local.example to web/.env.local and fill from Supabase → Settings → API Keys (publishable key).',
  )
}

// Publishable (anon) key only — RLS keeps this read-only from the browser.
export const supabase = createClient(url, key, {
  auth: { persistSession: false },
})
