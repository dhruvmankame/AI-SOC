import { createFileRoute } from "@tanstack/react-router";
import { Shell } from "@/components/soc/layout";
import { Analyze } from "@/components/soc/analyze";
export const Route = createFileRoute("/analyze")({ head:()=>({meta:[{title:"Analyze Flow Logs | AI-SOC"},{name:"description",content:"Upload CICIDS flow logs for local detection and evidence-grounded investigation in AI-SOC."},{property:"og:title",content:"Analyze Flow Logs | AI-SOC"},{property:"og:description",content:"Upload flow logs for detection and evidence-grounded investigation."},{property:"og:type",content:"website"},{name:"twitter:card",content:"summary_large_image"}]}),component:()=> <Shell title="Analyze" description="Turn network flow data into traceable, evidence-grounded investigations."><Analyze/></Shell> });
