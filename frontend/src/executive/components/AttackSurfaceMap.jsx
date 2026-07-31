import React from "react";
import "./AttackSurfaceMap.css";

export default function AttackSurfaceMap({
  attackGraph = {},
  threatMatrix = {},
  riskForecast = {}
}) {

const nodes = Array.isArray(attackGraph?.nodes)
  ? attackGraph.nodes
  : Object.values(attackGraph?.nodes || {});

const links = Array.isArray(attackGraph?.links)
  ? attackGraph.links
  : Array.isArray(attackGraph?.edges)
    ? attackGraph.edges
    : [];

const criticalAssets = nodes.filter(
  n => (n.max_score ?? n.score ?? 0) >= 90
);

const highRiskAssets = nodes.filter(n => {
  const score = n.max_score ?? n.score ?? 0;
  return score >= 70 && score < 90;
});


  const exposureScore = Math.min(
    100,
    criticalAssets.length * 15 +
    highRiskAssets.length * 8
  );


  const attackStages = [
    {
      title:"External Threat",
      icon:"🌍",
      count:nodes.filter(
        n=>n.category==="External"
      ).length
    },
    {
      title:"Initial Access",
      icon:"🎣",
      count:nodes.filter(
        n=>n.category==="Phishing"
      ).length
    },
    {
      title:"Credential Theft",
      icon:"🔐",
      count:nodes.filter(
        n=>n.category==="Credential"
      ).length
    },
    {
      title:"Enterprise Assets",
      icon:"🏢",
      count:nodes.length
    },
    {
      title:"Critical Systems",
      icon:"🚨",
      count:criticalAssets.length
    }
  ];


  return (

<section className="attack-surface-container">


<div className="attack-surface-header">

<div>

<h2>
🌐 Executive Attack Surface Map
</h2>

<p>
AI-powered visualization of attack paths,
risk propagation and enterprise exposure
</p>

</div>


<div className="surface-status">
LIVE AI MONITORING
</div>


</div>



<div className="exposure-banner">


<div>

<span>
Enterprise Exposure Score
</span>

<strong>
{exposureScore}%
</strong>

</div>


<div>

<span>
Attack Connections
</span>

<strong>
{links.length}
</strong>

</div>


<div>

<span>
Predicted Severity
</span>

<strong>
{riskForecast?.predictedSeverity || "Low"}
</strong>

</div>


</div>




<div className="surface-grid">


<div className="attack-chain">


<h3>
⚔ Attack Propagation Chain
</h3>



{attackStages.map((stage,index)=>(

<div
className="attack-stage"
key={index}
>


<div className="stage-icon">
{stage.icon}
</div>


<div className="stage-content">

<strong>
{stage.title}
</strong>

<span>
{stage.count} events detected
</span>

</div>


</div>

))}


</div>





<div className="surface-intelligence">


<h3>
🧠 AI Exposure Intelligence
</h3>



<div className="metric">

<span>
Total Attack Nodes
</span>

<strong>
{nodes.length}
</strong>

</div>



<div className="metric critical-text">

<span>
Critical Assets
</span>

<strong>
{criticalAssets.length}
</strong>

</div>




<div className="metric high-text">

<span>
High Risk Assets
</span>

<strong>
{highRiskAssets.length}
</strong>

</div>



<div className="metric">

<span>
Threat Probability
</span>

<strong>
{riskForecast?.probability || 0}%
</strong>

</div>



<h3>
🔥 Threat Landscape
</h3>


<div className="threat-bars">


<div>
Critical
<span>
{threatMatrix?.critical || 0}
</span>
</div>


<div>
High
<span>
{threatMatrix?.high || 0}
</span>
</div>


<div>
Medium
<span>
{threatMatrix?.medium || 0}
</span>
</div>


<div>
Low
<span>
{threatMatrix?.low || 0}
</span>
</div>


</div>


</div>


</div>


</section>

  );

}