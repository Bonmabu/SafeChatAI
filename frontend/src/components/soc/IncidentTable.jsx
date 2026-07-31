export default function IncidentTable({
  incidents,
  search,
  setSearch,
  severityFilter,
  setSeverityFilter,
  assigneeFilter,
  setAssigneeFilter,
  sortBy,
  setSortBy,
  currentPage,
  setCurrentPage,
  pageSize,
  resolveIncident,
  investigateIncident,
  assignIncident,
  setSelectedIncident
}) {

return (
<div
style={{
  background:"#111827",
  borderRadius:10,
  padding:10,
  height:"420px",
  overflow:"hidden",
  display:"flex",
  flexDirection:"column"
}}
>

<h2
style={{
color:"#38bdf8",
fontSize:"22px",
fontWeight:"700",
marginBottom:"15px"
}}
>
🚨 Incident Management
</h2>

<input
placeholder="Search incidents..."
value={search}
onChange={(e)=>setSearch(e.target.value)}
style={{
width:"100%",
padding:10,
marginBottom:10,
background:"#1f2937",
color:"white"
}}
/>


<select
value={severityFilter}
onChange={(e)=>setSeverityFilter(e.target.value)}
style={{
width:"100%",
padding:10,
marginBottom:10,
background:"#1f2937",
color:"white"
}}
>

<option value="ALL">All Priorities</option>
<option value="Critical">Critical</option>
<option value="High Risk">High Risk</option>
<option value="Medium">Medium</option>
<option value="Low">Low</option>

</select>


<div
style={{
  flex:1,
  overflowY:"auto",
  overflowX:"hidden",
  marginTop:10
}}
>

<table
style={{
  width:"100%",
  borderCollapse:"collapse",
  tableLayout:"fixed",
  fontSize:"14px"
}}
>

<thead
style={{
  position:"sticky",
  top:0,
  background:"#111827",
  zIndex:2
}}
>

<tr>
<th>ID</th>
<th>Category</th>
<th>Severity</th>
<th>Status</th>
<th>Assigned</th>
<th>Actions</th>
</tr>

</thead>


<tbody>

{incidents
.filter(i=>
i.category
?.toLowerCase()
.includes(search.toLowerCase())
)
.sort((a,b)=>{

if(sortBy==="HIGH"){

const order={
Critical:4,
"High Risk":3,
Medium:2,
Low:1
};

return (order[b.severity]||0)
-
(order[a.severity]||0);

}

return b.id-a.id;

})
.slice(
(currentPage-1)*pageSize,
currentPage*pageSize
)
.map(incident=>(

<tr
key={incident.id}
onClick={()=>{
setSelectedIncident(incident)
}}
>

<td>{incident.id}</td>

<td>{incident.category}</td>

<td>
{incident.severity}
</td>

<td>
{incident.status}
</td>

<td>
{incident.assigned_to || "Unassigned"}
</td>


<td>

<button
onClick={(e)=>{
e.stopPropagation();
assignIncident(incident.id)
}}
>
👤
</button>


<button
onClick={(e)=>{
e.stopPropagation();
investigateIncident(incident.id)
}}
>
🔍
</button>


<button
onClick={(e)=>{
e.stopPropagation();
resolveIncident(incident.id)
}}
>
✅
</button>

</td>


</tr>

))}

</tbody>

</table>
</div>


<div
style={{
marginTop:15,
display:"flex",
justifyContent:"space-between"
}}
>

<button
disabled={currentPage===1}
onClick={()=>
setCurrentPage(currentPage-1)
}
>
◀ Previous
</button>


<span>
Page {currentPage}
</span>


<button
disabled={
currentPage*pageSize >= incidents.length
}
onClick={()=>
setCurrentPage(currentPage+1)
}
>
Next ▶
</button>


</div>


</div>
);

}