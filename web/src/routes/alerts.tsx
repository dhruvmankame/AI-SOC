import { createFileRoute } from "@tanstack/react-router";
import { Shell } from "@/components/soc/layout";
import { Alerts } from "@/components/soc/alerts";
export const Route = createFileRoute("/alerts")({ head:()=>({meta:[{title:"Alert Queue | AI-SOC"},{name:"description",content:"Inspect deduplicated security alerts, detector contributions, and source evidence in AI-SOC."},{property:"og:title",content:"Alert Queue | AI-SOC"},{property:"og:description",content:"Inspect security alerts, detector contributions, and source evidence."},{property:"og:type",content:"website"},{name:"twitter:card",content:"summary_large_image"}]}),component:()=> <Shell title="Alert Queue" description="Deduplicated detector signals with source evidence on demand."><Alerts/></Shell> });
