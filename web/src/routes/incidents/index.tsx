import { createFileRoute } from "@tanstack/react-router";
import { Shell } from "@/components/soc/layout";
import { Incidents } from "@/components/soc/incidents";
export const Route = createFileRoute("/incidents/")({ head:()=>({meta:[{title:"Incidents | AI-SOC"},{name:"description",content:"Risk-ranked incident queue with MITRE context in the AI-SOC security operations workbench."},{property:"og:title",content:"Incidents | AI-SOC"},{property:"og:description",content:"Risk-ranked incident queue and investigation status."},{property:"og:type",content:"website"},{name:"twitter:card",content:"summary_large_image"}]}),component:()=> <Shell title="Incidents" description="Correlated attacks, ranked for analyst review."><Incidents/></Shell> });
