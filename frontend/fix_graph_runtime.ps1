$ErrorActionPreference = "Stop"

$dashboard = ".\src\executive\ExecutiveDashboard.jsx"
$attackGraphFile = ".\src\executive\components\AttackGraph.jsx"

Write-Host "=== GRAPH RUNTIME FIX ===" -ForegroundColor Cyan

if (!(Test-Path $dashboard)) {
    throw "Missing file: $dashboard"
}

if (!(Test-Path $attackGraphFile)) {
    throw "Missing file: $attackGraphFile"
}

Copy-Item $dashboard "$dashboard.backup-graph-fix" -Force
Copy-Item $attackGraphFile "$attackGraphFile.backup-graph-fix" -Force

# ============================================================
# EXECUTIVE DASHBOARD
# ============================================================

$text = Get-Content $dashboard -Raw

# Remove a previously inserted normalizeGraphData function.
$text = [regex]::Replace(
    $text,
    '(?s)const normalizeGraphData\s*=\s*\(graph\)\s*=>\s*\{.*?\n\};\s*',
    ''
)

$function = @"
const normalizeGraphData = (graph) => {
  const rawNodes = Array.isArray(graph?.nodes)
    ? graph.nodes
    : Object.values(graph?.nodes || {});

  const rawLinks = Array.isArray(graph?.links)
    ? graph.links
    : Array.isArray(graph?.edges)
      ? graph.edges
      : [];

  const validNodes = rawNodes.filter((node) => {
    if (!node || node.id === undefined || node.id === null) {
      return false;
    }

    const id = String(node.id).trim();

    return (
      id !== "" &&
      id.toLowerCase() !== "none" &&
      id.toLowerCase() !== "null" &&
      id.toLowerCase() !== "undefined"
    );
  });

  const nodeIds = new Set(
    validNodes.map((node) => String(node.id).trim())
  );

  const validLinks = rawLinks.filter((link) => {
    if (!link) {
      return false;
    }

    const source =
      typeof link.source === "object"
        ? link.source?.id
        : link.source;

    const target =
      typeof link.target === "object"
        ? link.target?.id
        : link.target;

    if (
      source === undefined ||
      source === null ||
      target === undefined ||
      target === null
    ) {
      return false;
    }

    const sourceId = String(source).trim();
    const targetId = String(target).trim();

    if (
      !sourceId ||
      !targetId ||
      sourceId.toLowerCase() === "none" ||
      targetId.toLowerCase() === "none" ||
      sourceId.toLowerCase() === "null" ||
      targetId.toLowerCase() === "null" ||
      sourceId.toLowerCase() === "undefined" ||
      targetId.toLowerCase() === "undefined"
    ) {
      return false;
    }

    return (
      nodeIds.has(sourceId) &&
      nodeIds.has(targetId)
    );
  });

  return {
    nodes: validNodes,
    links: validLinks
  };
};

"@

# Insert function immediately before the component declaration.
$componentMarker = "export default function ExecutiveDashboard"

if ($text.Contains($componentMarker)) {
    $text = $text.Replace(
        $componentMarker,
        "$function`r`n$componentMarker"
    )
}
elseif ($text.Contains("function ExecutiveDashboard")) {
    $text = $text.Replace(
        "function ExecutiveDashboard",
        "$function`r`nfunction ExecutiveDashboard"
    )
}
else {
    throw "Could not locate ExecutiveDashboard component declaration."
}

# Replace the existing main graphData object.
$pattern = '(?s)graphData=\{\{\s*nodes:\s*Array\.isArray\(attackGraph\?\.nodes\).*?links:\s*Array\.isArray\(attackGraph\?\.links\).*?\}\}'

$replacement = 'graphData={normalizeGraphData(attackGraph)}'

$text = [regex]::Replace(
    $text,
    $pattern,
    $replacement,
    1
)

Set-Content $dashboard $text -Encoding UTF8

# ============================================================
# ATTACK GRAPH COMPONENT
# ============================================================

$graph = Get-Content $attackGraphFile -Raw

$pattern2 = '(?s)// Always provide arrays to ForceGraph2D.*?const safeLinks = .*?: \[\];'

$replacement2 = @"
  // Normalize and validate graph data before ForceGraph2D.
  const rawNodes = Array.isArray(attackGraph?.nodes)
    ? attackGraph.nodes
    : Object.values(attackGraph?.nodes || {});

  const rawLinks = Array.isArray(attackGraph?.links)
    ? attackGraph.links
    : Array.isArray(attackGraph?.edges)
      ? attackGraph.edges
      : [];

  const safeNodes = rawNodes.filter((node) => {
    if (!node || node.id === undefined || node.id === null) {
      return false;
    }

    const id = String(node.id).trim();

    return (
      id !== "" &&
      id.toLowerCase() !== "none" &&
      id.toLowerCase() !== "null" &&
      id.toLowerCase() !== "undefined"
    );
  });

  const nodeIds = new Set(
    safeNodes.map((node) => String(node.id).trim())
  );

  const safeLinks = rawLinks.filter((link) => {
    if (!link) {
      return false;
    }

    const source =
      typeof link.source === "object"
        ? link.source?.id
        : link.source;

    const target =
      typeof link.target === "object"
        ? link.target?.id
        : link.target;

    if (
      source === undefined ||
      source === null ||
      target === undefined ||
      target === null
    ) {
      return false;
    }

    const sourceId = String(source).trim();
    const targetId = String(target).trim();

    if (
      !sourceId ||
      !targetId ||
      sourceId.toLowerCase() === "none" ||
      targetId.toLowerCase() === "none" ||
      sourceId.toLowerCase() === "null" ||
      targetId.toLowerCase() === "null" ||
      sourceId.toLowerCase() === "undefined" ||
      targetId.toLowerCase() === "undefined"
    ) {
      return false;
    }

    return (
      nodeIds.has(sourceId) &&
      nodeIds.has(targetId)
    );
  });
"@

if ([regex]::IsMatch($graph, $pattern2)) {
    $graph = [regex]::Replace(
        $graph,
        $pattern2,
        $replacement2,
        1
    )
}
else {
    Write-Host "AttackGraph validation block was not found; leaving that component unchanged." -ForegroundColor Yellow
}

Set-Content $attackGraphFile $graph -Encoding UTF8

# ============================================================
# VERIFICATION
# ============================================================

Write-Host ""
Write-Host "Dashboard verification:" -ForegroundColor Cyan

Select-String `
    -Path $dashboard `
    -Pattern "normalizeGraphData|graphData=\{normalizeGraphData" |
    ForEach-Object {
        Write-Host ("LINE {0}: {1}" -f $_.LineNumber, $_.Line.Trim())
    }

Write-Host ""
Write-Host "AttackGraph verification:" -ForegroundColor Cyan

Select-String `
    -Path $attackGraphFile `
    -Pattern "rawNodes|rawLinks|nodeIds|safeNodes|safeLinks" |
    ForEach-Object {
        Write-Host ("LINE {0}: {1}" -f $_.LineNumber, $_.Line.Trim())
    }

Write-Host ""
Write-Host "Backups:" -ForegroundColor Green
Write-Host (Resolve-Path "$dashboard.backup-graph-fix")
Write-Host (Resolve-Path "$attackGraphFile.backup-graph-fix")

Write-Host ""
Write-Host "=== GRAPH RUNTIME FIX COMPLETE ===" -ForegroundColor Green
