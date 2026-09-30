import { createFileRoute } from "@tanstack/react-router";
import { Shell } from "@/components/soc/layout";
import { Overview } from "@/components/soc/overview";

export const Route = createFileRoute("/")({
  head: () => ({ meta: [
    { title: "Overview | AI-SOC" },
    { name: "description", content: "AI-SOC security operations overview: real CICIDS seed metrics, alert evidence, and risk-ranked incidents." },
    { property: "og:title", content: "Overview | AI-SOC" },
    { property: "og:description", content: "Security operations overview with detection metrics and risk-ranked incidents." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary_large_image" },
  ] }),
  component: Index,
});

function Index() {
  return <Shell title="Overview" description="A clear view of signals, correlation, and investigation priority."><Overview /></Shell>;
}
