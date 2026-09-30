<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

- Keep AI-SOC content routes in TanStack Start and the shared analyst shell in `src/components/soc` because this workspace's router is fixed and all screens need consistent navigation.
- The unconnected preview uses a static snapshot extracted from the linked repository's CICIDS seed SQL; always identify it as a snapshot because simulated live telemetry would mislead analysts.
- CSV analysis calls the original project's local-only agents service via `VITE_ANALYZE_API` or localhost:8787; do not expose privileged write operations through this frontend because the original service is unauthenticated and local-only.
