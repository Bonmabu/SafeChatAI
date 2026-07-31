import ForceGraph2D from "react-force-graph-2d";

export default function AttackGraph({
  graphRef,
  graphData,
  selectedNode,
  setSelectedNode,
  highlightNodes,
  setHighlightNodes,
  highlightLinks,
  setHighlightLinks
}) {

const getRiskColor = {
  critical:"#ff0033",
  high:"#ff7a00",
  medium:"#ffd000",
  low:"#00ff88"
};

return (
<div
style={{
  width:"100%",
  height:"100%",
  background:"#0b1220",
  border:"1px solid #1f2937",
  borderRadius:10,
  padding:10,
  overflow:"hidden",
  boxSizing:"border-box"
}}
>

<h2 style={{margin:"0 0 5px 0"}}>
🔗 Live Attack Graph
</h2>

<p style={{margin:"5px"}}>
Nodes: {graphData.nodes.length}
<br/>
Links: {graphData.links.length}
</p>

<div
style={{
  width:"100%",
  height:"420px",
  overflow:"hidden"
}}
>

<ForceGraph2D

ref={graphRef}

graphData={graphData}

width={900}
height={420}

nodeRelSize={4}

onNodeClick={(node)=>{

setSelectedNode(node);

const nodes=new Set([node.id]);
const links=new Set();

graphData.links.forEach(link=>{

const source =
typeof link.source==="object"
? link.source.id
: link.source;

const target =
typeof link.target==="object"
? link.target.id
: link.target;

if(source===node.id || target===node.id){

nodes.add(source);
nodes.add(target);
links.add(link);

}

});

setHighlightNodes(nodes);
setHighlightLinks(links);

}}

onBackgroundClick={()=>{

setSelectedNode(null);
setHighlightNodes(new Set());
setHighlightLinks(new Set());

}}


nodeCanvasObject={(node,ctx,scale)=>{

const radius =
node.riskLevel==="critical"?6:
node.riskLevel==="high"?5:
node.riskLevel==="medium"?4:3;


ctx.beginPath();

ctx.arc(
node.x,
node.y,
radius,
0,
Math.PI*2
);


ctx.fillStyle =
getRiskColor[node.riskLevel] || "#00ffff";

ctx.fill();


ctx.font=`${12/scale}px Arial`;

ctx.fillStyle="#fff";

ctx.fillText(
`${node.category} (${node.score})`,
node.x+radius+4,
node.y
);

}}

/>

</div>

</div>
);

}