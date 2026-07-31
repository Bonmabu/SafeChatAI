import React from "react";
import "./CommandCenter.css";

export default function CommandCenter({
  attackGraph = {},
  incidents = [],
  alerts = [],
  securityPosture = {},
  riskForecast = {},
}) {
const commandCenter = {
  status: securityPosture.threat_level || "Healthy",

  attackRate: alerts.length,

  mttd: riskForecast.mttd ?? 3.2,

  mttr: riskForecast.mttr ?? 7.8,

  aiConfidence: riskForecast.aiConfidence ?? 97,

  threatTemperature: securityPosture.score ?? 35,
};

return (

<section className="command-center">


<div className="command-header">

<div>

<h2>
🛡 Executive Command Center
</h2>

<p>
Real-time enterprise security posture monitoring
</p>

</div>


<div className="command-status">
{commandCenter.status || "Healthy"}
</div>


</div>




<div className="command-grid">


<div className="command-card">

<span>
Attack Rate
</span>

<strong>
{commandCenter.attackRate}
</strong>

<p>
events/min
</p>

</div>




<div className="command-card">

<span>
MTTD
</span>

<strong>
{commandCenter.mttd}
</strong>

<p>
minutes
</p>

</div>





<div className="command-card">

<span>
MTTR
</span>

<strong>
{commandCenter.mttr}
</strong>

<p>
minutes
</p>

</div>






<div className="command-card">

<span>
AI Confidence
</span>

<strong>
{commandCenter.aiConfidence}%
</strong>

<p>
decision accuracy
</p>

</div>



</div>





<div className="risk-container">


<div className="risk-header">

<span>
Enterprise Threat Temperature
</span>

<strong>
{commandCenter.threatTemperature}%
</strong>

</div>



<div className="risk-bar">

<div
className="risk-progress"
style={{
width:`${commandCenter.threatTemperature}%`
}}
/>

</div>



</div>



</section>

);

}