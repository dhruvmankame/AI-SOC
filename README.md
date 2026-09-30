# AI-SOC frontend handoff

This is the standalone Lovable frontend developed for the AI-SOC repository. It is not an automatic modification of your local clone or a drop-in replacement for the original `web/` app: this frontend uses TanStack Start, while the original frontend has its own setup. Keep the existing backend, data, and original files intact.

## Add it to your existing AI-SOC clone

1. Extract this ZIP. Copy the enclosed `ai-soc-frontend` folder into the root of your local AI-SOC clone, alongside `web/` (do not overwrite `web/`).
2. From that folder, install dependencies and start the frontend:

   ```sh
   cd ai-soc-frontend
   bun install
   bun run dev
   ```

   Alternatively, `npm install` and `npm run dev` work with Node.js.
3. The Overview, Incidents, Alert Queue, and Incident Record screens show a **static CICIDS2017 seed snapshot**, not live telemetry. CSV analysis calls the original project's local-only agents service at `http://localhost:8787` by default; set `VITE_ANALYZE_API` to your local service URL if different. The service must be started separately using the original repository's instructions. Do not expose its unauthenticated endpoint publicly.
4. Review locally, then commit and push the new folder from your AI-SOC repository as you normally do. This does not change the existing `web/` app or make the new frontend the default launch target automatically.

The blue pointer dot trails mouse movement for 1.2 seconds. Touch pointers do not show the dot, and reduced-motion settings disable the movement animation.
