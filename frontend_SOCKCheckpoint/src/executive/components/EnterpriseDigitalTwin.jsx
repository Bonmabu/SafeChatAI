import React from "react";
import "./EnterpriseDigitalTwin.css";

export default function EnterpriseDigitalTwin({
    attackGraph = {},
    securityPosture = {}
}) {


const nodes = Array.isArray(attackGraph?.nodes)
    ? attackGraph.nodes
    : Object.values(attackGraph?.nodes || {});


const links = Array.isArray(attackGraph?.links)
    ? attackGraph.links
    : [];


const assets = [
    {
        name:"Internet",
        icon:"🌍",
        keywords:["internet","external","ip"]
    },
    {
        name:"Firewall",
        icon:"🛡",
        keywords:["firewall","gateway"]
    },
    {
        name:"Email Gateway",
        icon:"📧",
        keywords:["email","phishing","mail"]
    },
    {
        name:"Identity",
        icon:"🔑",
        keywords:["identity","credential","login","password"]
    },
    {
        name:"Enterprise Servers",
        icon:"🖥",
        keywords:["server","endpoint","host"]
    },
    {
        name:"Databases",
        icon:"🗄",
        keywords:["database","sql","data"]
    },
    {
        name:"Finance",
        icon:"💰",
        keywords:["bank","finance","payment"]
    }
];



const getThreatCount = (asset) => {

    return nodes.filter(node => {

        const category = (node.category || "").toLowerCase();
        const stage = (node.stage || "").toLowerCase();
        const mitre = (node.mitre || "").toLowerCase();

        switch (asset.name) {

            case "Internet":
                return (
                    stage.includes("initial") ||
                    stage.includes("recon") ||
                    category.includes("scan") ||
                    category.includes("network")
                );

            case "Firewall":
                return (
                    category.includes("firewall") ||
                    category.includes("blocked") ||
                    stage.includes("defense")
                );

            case "Email Gateway":
                return (
                    category.includes("phishing") ||
                    category.includes("email") ||
                    category.includes("spam")
                );

            case "Identity":
                return (
                    category.includes("credential") ||
                    category.includes("password") ||
                    category.includes("login") ||
                    mitre.includes("credential")
                );

            case "Enterprise Servers":
                return (
                    category.includes("server") ||
                    category.includes("malware") ||
                    category.includes("ransomware") ||
                    stage.includes("execution")
                );

            case "Databases":
                return (
                    category.includes("database") ||
                    stage.includes("collection") ||
                    stage.includes("exfiltration")
                );

            case "Finance":
                return (
                    category.includes("bank") ||
                    category.includes("payment") ||
                    category.includes("fraud")
                );

            default:
                return false;
        }

    }).length;

};



return (

<section className="digital-twin">


<div className="digital-header">

<h2>
🏢 Enterprise Digital Twin
</h2>

<span className="live">
LIVE
</span>

</div>



<p>
Real-time enterprise attack surface visualization
</p>



<div className="asset-grid">


{
assets.map(asset=>{

const threats=getThreatCount(asset);


return (

<div
key={asset.name}
className="asset-card"
>

<h3>
{asset.icon}
{asset.name}
</h3>


<div className="asset-number">
{threats}
</div>


<span>
Detected Threat Links
</span>


<div
className="asset-bar"
>

<div
style={{
width:`${Math.min(threats*10,100)}%`
}}
/>

</div>


</div>


)

})
}



</div>



<div className="digital-summary">


<div>
<h4>Active Attack Paths</h4>
<strong>
{links.length}
</strong>
</div>


<div>
<h4>Assets Monitored</h4>
<strong>
{assets.length}
</strong>
</div>


<div>
<h4>Protected Assets</h4>
<strong>
{securityPosture?.protected_assets ?? 0}
</strong>
</div>


</div>



</section>


);

}