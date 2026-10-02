import { Link, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  ArrowUpRight,
  Bell,
  CircleHelp,
  DatabaseZap,
  LayoutDashboard,
  Radar,
  Shield,
  ShieldAlert,
  UploadCloud,
} from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import {
  ACTIVE_BATCH_EVENT,
  getActiveBatchId,
  setActiveBatchId,
  type ActiveBatchId,
} from "@/lib/active-batch";
import { fetchBatches, type BatchRow } from "@/lib/live-api";

const navigation = [
  { label: "Overview", to: "/" as const, icon: LayoutDashboard },
  { label: "Analyze", to: "/analyze" as const, icon: Radar },
  { label: "Incidents", to: "/incidents" as const, icon: ShieldAlert },
  { label: "Alert Queue", to: "/alerts" as const, icon: Bell },
];

function PointerDot() {
  const dot = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const element = dot.current;
    if (!element) return;
    let positioned = false;
    const onMove = (event: PointerEvent) => {
      if (event.pointerType !== "mouse") { element.classList.remove("is-visible"); return; }
      if (!positioned) {
        element.style.transition = "none";
        element.style.transform = `translate3d(${event.clientX}px, ${event.clientY}px, 0) translate(-50%, -50%)`;
        void element.offsetWidth;
        element.style.transition = "";
        positioned = true;
      } else {
        element.style.transform = `translate3d(${event.clientX}px, ${event.clientY}px, 0) translate(-50%, -50%)`;
      }
      element.classList.add("is-visible");
    };
    const onLeave = () => element.classList.remove("is-visible");
    window.addEventListener("pointermove", onMove, { passive: true });
    document.addEventListener("pointerleave", onLeave);
    window.addEventListener("blur", onLeave);
    return () => {
      window.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerleave", onLeave);
      window.removeEventListener("blur", onLeave);
    };
  }, []);
  return <div ref={dot} className="soc-pointer-dot" aria-hidden="true" />;
}

export function Shell({ title, description, children, action }: { title: string; description: string; children: ReactNode; action?: ReactNode }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const [batches, setBatches] = useState<BatchRow[]>([]);
  const [current, setCurrent] = useState<ActiveBatchId>("seed");

  useEffect(() => {
    let live = true;
    const refresh = () => {
      setCurrent(getActiveBatchId());
      void fetchBatches().then((rows) => live && setBatches(rows)).catch(() => {});
    };
    refresh();
    window.addEventListener(ACTIVE_BATCH_EVENT, refresh);
    return () => {
      live = false;
      window.removeEventListener(ACTIVE_BATCH_EVENT, refresh);
    };
  }, []);

  const knownCurrent = current === "seed" || batches.some((batch) => batch.batch_id === current);
  const selected = current === "seed" ? null : batches.find((batch) => batch.batch_id === current);
  const selectedLabel = current === "seed" ? "CICIDS Seed" : selected?.label || selected?.source_filename || "Current upload";

  function chooseDataset(value: string) {
    setActiveBatchId(value as ActiveBatchId);
    setCurrent(value as ActiveBatchId);
    window.location.reload();
  }

  return <div className="min-h-screen bg-background text-foreground lg:flex">
    <PointerDot />
    <aside className="relative z-20 flex shrink-0 flex-col border-b border-border bg-panel/75 backdrop-blur-xl lg:fixed lg:inset-y-0 lg:left-0 lg:w-[232px] lg:border-b-0 lg:border-r">
      <div className="flex h-[76px] items-center gap-3 border-b border-border/70 px-5">
        <div className="flex size-9 items-center justify-center rounded-md border border-primary/35 bg-primary/10 text-primary"><Shield className="size-5" strokeWidth={1.8}/></div>
        <div><div className="font-display text-[17px] font-bold leading-none">AI<span className="text-primary">·</span>SOC</div><div className="mt-1.5 font-mono text-[9px] uppercase text-faint">Evidence-first security</div></div>
      </div>
      <div className="hidden px-5 pt-8 font-mono text-[10px] uppercase text-faint lg:block">Workspace / 01</div>
      <nav aria-label="Main navigation" className="flex gap-1 overflow-x-auto px-3 py-3 lg:mt-3 lg:flex-col lg:overflow-visible lg:py-0">
        {navigation.map(({ label, to, icon: Icon }) => {
          const active = to === "/" ? pathname === "/" : pathname.startsWith(to);
          return <Link key={to} to={to} className={`soc-nav-link flex shrink-0 items-center gap-3 rounded-md px-3 py-2.5 text-[13px] ${active ? "border border-primary/25 bg-primary/10 font-semibold text-primary" : "border border-transparent text-muted-foreground hover:text-foreground"}`}>
            <Icon className="size-[17px]" strokeWidth={1.8}/><span>{label}</span>
          </Link>;
        })}
      </nav>
      <div className="mt-auto hidden px-4 pb-5 lg:block"><div className="border-t border-border pt-5"><div className="mb-3 flex items-center gap-2 text-xs text-muted-foreground"><span className="size-1.5 rounded-full bg-primary"/> Current dataset</div><div className="rounded-md border border-border bg-panel2/50 p-3"><div className="flex items-center gap-2 text-xs font-medium"><DatabaseZap className="size-4 text-primary"/><span className="truncate" title={selectedLabel}>{selectedLabel}</span></div><p className="mb-0 mt-2 text-[11px] leading-relaxed text-muted-foreground">Overview, alerts and incidents are isolated to this dataset.</p></div></div></div>
    </aside>
    <div className="min-w-0 flex-1 lg:ml-[232px]">
      <header className="relative z-10 flex min-h-[76px] flex-wrap items-center justify-between gap-3 border-b border-border bg-background/85 px-5 py-3 backdrop-blur-lg lg:px-8">
        <div><div className="flex items-center gap-2 font-mono text-[10px] uppercase text-faint"><span>AI-SOC</span><span>/</span><span className="text-primary">{title}</span></div><h1 className="mt-1 font-display text-xl font-semibold leading-tight">{title}</h1></div>
        <div className="flex flex-wrap items-center gap-3">{action}
          <label className="hidden items-center gap-2 rounded-md border border-border bg-panel px-2.5 py-1.5 sm:flex">
            <span className="font-mono text-[9px] uppercase text-faint">Dataset</span>
            <select value={current} onChange={(e)=>chooseDataset(e.target.value)} className="max-w-[220px] bg-transparent text-xs text-foreground outline-none [&>option]:bg-panel [&>option]:text-foreground" aria-label="Current dataset">
              <option value="seed" className="bg-panel text-foreground">CICIDS Seed</option>
              {!knownCurrent && current !== "seed" && <option value={current} className="bg-panel text-foreground">Current upload</option>}
              {batches.map((batch)=><option key={batch.batch_id} value={batch.batch_id} className="bg-panel text-foreground">{batch.label || batch.source_filename || batch.batch_id.slice(0,8)}</option>)}
            </select>
          </label>
          <Link to="/analyze"><Button size="sm" className="gap-2"><UploadCloud className="size-4"/><span className="hidden sm:inline">Analyze CSV</span><span className="sm:hidden">Analyze</span></Button></Link>
        </div>
      </header>
      <main className="mx-auto max-w-[1560px] px-5 pb-16 pt-7 lg:px-8">
        <div className="mb-7 flex flex-wrap items-end justify-between gap-2"><div><div className="mb-2 flex items-center gap-2 font-mono text-[10px] font-medium uppercase text-primary"><Activity className="size-3"/> Detection plane <span className="text-faint">/</span> Investigation plane</div><p className="text-sm text-muted-foreground">{description}</p></div><span className="inline-flex max-w-sm items-center gap-1.5 truncate font-mono text-[10px] uppercase text-faint" title={selectedLabel}><CircleHelp className="size-3 shrink-0"/> {selectedLabel}</span></div>
        {children}
      </main>
    </div>
  </div>;
}

export function SectionTitle({ label, aside, href }: { label: string; aside?: string; href?: "/incidents" | "/alerts" }) {
  return <div className="flex min-h-14 flex-wrap items-center justify-between gap-3 border-b border-border/75 px-5 py-3"><div><h2 className="font-display text-sm font-semibold">{label}</h2>{aside && <p className="mt-0.5 text-[11px] text-faint">{aside}</p>}</div>{href && <Link to={href} className="soc-text-link inline-flex items-center gap-1 font-mono text-[10px] font-medium uppercase text-primary hover:underline">View all <ArrowUpRight className="size-3"/></Link>}</div>;
}

export function Severity({ value }: { value: string }) {
  const tone = value === "critical" ? "text-crit bg-crit/10 border-crit/25" : value === "high" ? "text-high bg-high/10 border-high/25" : value === "medium" ? "text-med bg-med/10 border-med/25" : value === "info" ? "text-info bg-info/10 border-info/25" : "text-low bg-low/10 border-low/25";
  return <span className={`inline-flex items-center gap-1.5 rounded border px-2 py-1 font-mono text-[10px] font-medium uppercase ${tone}`}><span className="size-1.5 rounded-full bg-current"/>{value}</span>;
}

export function EmptyState({ title, detail }: { title: string; detail: string }) {
  return <div className="flex min-h-32 flex-col items-center justify-center px-5 py-8 text-center"><p className="text-sm font-medium">{title}</p><p className="mt-1 max-w-md text-xs leading-relaxed text-muted-foreground">{detail}</p></div>;
}
