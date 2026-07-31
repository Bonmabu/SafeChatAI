import React from "react";
import {
  Radar,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  ResponsiveContainer
} from "recharts";

import "./ExecutiveRiskRadar.css";

export default function ExecutiveRiskRadar({
  securityPosture = {},
  threatIntelligence = {},
  executiveAI = {}
}) {

  const radarData = [
    {
      subject: "Security",
      value: securityPosture.security_score ?? 0,
      fullMark: 100
    },
    {
      subject: "SOC Health",
      value: securityPosture.soc_health ?? 0,
      fullMark: 100
    },
    {
      subject: "Threats",
      value: Math.min(
        securityPosture.critical_threats ?? 0,
        100
      ),
      fullMark: 100
    },
    {
      subject: "Anomaly",
      value: Math.min(
        threatIntelligence?.anomaly?.deviation_percent ?? 0,
        100
      ),
      fullMark: 100
    },
    {
      subject: "Forecast",
      value:
        threatIntelligence?.forecast?.forecast_score ?? 0,
      fullMark: 100
    },
    {
      subject: "Stability",
      value:
        Math.max(0, 100 - (executiveAI?.instability_score ?? 0)),
      fullMark: 100
    }
  ];

  return (

<div className="executive-risk-radar">

<div className="risk-header">

<div>

<h2>📡 Executive Risk Radar</h2>

<p>
Live AI risk analysis across the enterprise
</p>

</div>

<div
className="risk-status"
style={{
background:
securityPosture.enterprise_status === "CRITICAL"
? "#7f1d1d"
: "#064e3b"
}}
>
{securityPosture.enterprise_status}
</div>

</div>

<div className="risk-grid">

<div className="risk-chart">

<ResponsiveContainer
width="100%"
height={420}
>

<RadarChart data={radarData}>

<PolarGrid />

<PolarAngleAxis
dataKey="subject"
/>

<PolarRadiusAxis
domain={[0,100]}
/>

<Radar
dataKey="value"
stroke="#00ffc8"
fill="#00ffc8"
fillOpacity={0.45}
/>

</RadarChart>

</ResponsiveContainer>

</div>

<div className="risk-summary">

<div className="metric">

<span>Security Score</span>

<strong>
{securityPosture.security_score ?? 0}%
</strong>

</div>

<div className="metric">

<span>Threat Level</span>

<strong>
{securityPosture.threat_level}
</strong>

</div>

<div className="metric">

<span>Critical Threats</span>

<strong>
{securityPosture.critical_threats}
</strong>

</div>

<div className="metric">

<span>SOC Health</span>

<strong>
{securityPosture.soc_health}%
</strong>

</div>

<div className="metric">

<span>Breach Prediction</span>

<strong>
{securityPosture.risk_prediction}
</strong>

</div>

<div className="metric">

<span>AI Decision</span>

<strong>
{executiveAI?.executive_decision ?? "Analyzing..."}
</strong>

</div>

<div className="metric">

<span>Threat Velocity</span>

<strong>
{threatIntelligence?.velocity?.threats_per_minute ?? 0}/min
</strong>

</div>

<div className="metric">

<span>Anomaly</span>

<strong>
{threatIntelligence?.anomaly?.anomaly_level}
</strong>

</div>

</div>

</div>

</div>

  );
}