"use strict";

if (typeof cytoscapeDagre !== "undefined") {
  cytoscape.use(cytoscapeDagre);
}
if (typeof cytoscapeNodeHtmlLabel !== "undefined") {
  cytoscape.use(cytoscapeNodeHtmlLabel);
}

const dom = {
  statusBadge: document.getElementById("statusBadge"),
  togglePanelsBtn: document.getElementById("togglePanelsBtn"),
  loadLastBtn: document.getElementById("loadLastBtn"),
  runObfBtn: document.getElementById("runObfBtn"),
  loadCompareBtn: document.getElementById("loadCompareBtn"),

  exePathInput: document.getElementById("exePathInput"),
  cfgPathInput: document.getElementById("cfgPathInput"),
  profileSelect: document.getElementById("profileSelect"),
  seedInput: document.getElementById("seedInput"),
  strictUnwindInput: document.getElementById("strictUnwindInput"),
  rewritePolicySelect: document.getElementById("rewritePolicySelect"),
  sectionLayoutSelect: document.getElementById("sectionLayoutSelect"),

  leftJsonPathInput: document.getElementById("leftJsonPathInput"),
  rightJsonPathInput: document.getElementById("rightJsonPathInput"),
  mapJsonPathInput: document.getElementById("mapJsonPathInput"),

  searchInput: document.getElementById("searchInput"),
  sortBtn: document.getElementById("sortBtn"),
  listStats: document.getElementById("listStats"),
  functionList: document.getElementById("functionList"),

  selectedFnName: document.getElementById("selectedFnName"),
  selectedOldAddr: document.getElementById("selectedOldAddr"),
  selectedNewAddr: document.getElementById("selectedNewAddr"),
  selectedMutation: document.getElementById("selectedMutation"),
  selectedFallback: document.getElementById("selectedFallback"),

  passProfile: document.getElementById("passProfile"),
  passSeed: document.getElementById("passSeed"),
  rewrittenBytes: document.getElementById("rewrittenBytes"),
  passList: document.getElementById("passList"),
  passStatsBody: document.getElementById("passStatsBody"),

  leftFnMeta: document.getElementById("leftFnMeta"),
  rightFnMeta: document.getElementById("rightFnMeta"),

  cyLeft: document.getElementById("cyLeft"),
  cyRight: document.getElementById("cyRight"),
  graphTools: Array.from(document.querySelectorAll(".graph-tool")),
};

const state = {
  leftPayload: null,
  rightPayload: null,
  mapPayload: null,
  selectedLeftId: null,
  filteredLeftFunctions: [],
  sortByNameAsc: false,
  cy: {
    left: null,
    right: null,
  },
  indexes: null,
  running: false,
};

const UI_COMPACT_KEY = "cfg_viewer_compact_panels";

function setCompactPanels(compact) {
  if (compact) {
    document.body.classList.add("compact-panels");
    dom.togglePanelsBtn.innerHTML = '<i class="ph ph-layout"></i> Afficher outils';
  } else {
    document.body.classList.remove("compact-panels");
    dom.togglePanelsBtn.innerHTML = '<i class="ph ph-layout"></i> Masquer outils';
  }
  try {
    window.localStorage.setItem(UI_COMPACT_KEY, compact ? "1" : "0");
  } catch (_) {
    // ignore storage errors
  }
}

function initCompactPanels() {
  let compact = true;
  try {
    const stored = window.localStorage.getItem(UI_COMPACT_KEY);
    if (stored === "0") compact = false;
    if (stored === "1") compact = true;
  } catch (_) {
    // ignore storage errors
  }
  setCompactPanels(compact);
}

function setStatus(kind, text) {
  dom.statusBadge.className = `status-badge ${kind}`;
  dom.statusBadge.textContent = text;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function coerceNumber(value) {
  if (typeof value === "number" && Number.isFinite(value)) return Math.trunc(value);
  if (typeof value !== "string") return null;
  const s = value.trim().toLowerCase();
  if (!s) return null;
  if (s.startsWith("0x")) {
    const v = Number.parseInt(s.slice(2), 16);
    return Number.isFinite(v) ? v : null;
  }
  if (/^-?[0-9]+$/.test(s)) {
    const v = Number.parseInt(s, 10);
    return Number.isFinite(v) ? v : null;
  }
  if (/^[0-9a-f]+$/.test(s)) {
    const v = Number.parseInt(s, 16);
    return Number.isFinite(v) ? v : null;
  }
  return null;
}

function parseHexNumber(value) {
  return coerceNumber(value);
}

function formatHex(value) {
  const n = coerceNumber(value);
  if (n === null) return "-";
  return `0x${n.toString(16)}`;
}

function normName(name) {
  return String(name || "").trim().toLowerCase();
}

function layoutOptions() {
  return {
    name: "dagre",
    rankDir: "TB",
    rankSep: 94,
    nodeSep: 44,
    edgeSep: 20,
    animate: false,
    fit: true,
    padding: 28,
  };
}

function graphStyle() {
  return [
    {
      selector: "node",
      style: {
        shape: "rectangle",
        width: "data(render_width)",
        height: "data(render_height)",
        "background-color": "transparent",
        "border-width": 0,
        label: "",
      },
    },
    {
      selector: "edge",
      style: {
        width: 1.8,
        "line-color": "#454b54",
        "target-arrow-color": "#454b54",
        "target-arrow-shape": "triangle",
        "curve-style": "taxi",
        "taxi-direction": "downward",
        "taxi-turn": 24,
        "taxi-turn-min-distance": 8,
      },
    },
    {
      selector: "edge.branch-true",
      style: {
        "line-color": "#4CAF50",
        "target-arrow-color": "#4CAF50",
      },
    },
    {
      selector: "edge.branch-false",
      style: {
        "line-color": "#e55566",
        "target-arrow-color": "#e55566",
      },
    },
    {
      selector: "edge.unconditional",
      style: {
        "line-color": "#569CD6",
        "target-arrow-color": "#569CD6",
      },
    },
    {
      selector: "edge.call",
      style: {
        "line-color": "#D7BA7D",
        "target-arrow-color": "#D7BA7D",
        "line-style": "dashed",
      },
    },
    {
      selector: "edge.loop-back",
      style: {
        width: 3.2,
      },
    },
    {
      selector: "edge.indirect",
      style: {
        "line-style": "dotted",
      },
    },
  ];
}

function tokenHtml(token) {
  const kind = token && token.kind ? token.kind : "text";
  const text = token && token.text ? token.text : "";
  return `<span class="inst-token ${escapeHtml(kind)}">${escapeHtml(text)}</span>`;
}

function lineHtml(line, index) {
  const tokens = Array.isArray(line && line.tokens) ? line.tokens : [];
  const n = String(index + 1).padStart(2, "0");
  return (
    `<div class="node-line"><span class="node-lineno">${n}</span><span>` +
    tokens.map((t) => tokenHtml(t)).join("") +
    "</span></div>"
  );
}

function buildFallbackLabel(data) {
  const lines = Array.isArray(data && data.instructions) ? data.instructions : [];
  if (!lines.length) {
    return String((data && (data.title || data.label)) || "nœud");
  }
  const rendered = lines.map((line, index) => {
    const tokens = Array.isArray(line && line.tokens) ? line.tokens : [];
    const text = tokens.map((t) => String((t && t.text) || "")).join("").trim();
    return `${String(index + 1).padStart(2, "0")} ${text}`;
  });
  const truncated = Number(data && data.preview_truncated) || 0;
  if (truncated > 0) rendered.push(`+${truncated} instructions`);
  return rendered.join("\n");
}

function estimateNodeWidth(node) {
  const data = node && node.data ? node.data : {};
  if (data.node_kind === "group") return 220;

  if (data.node_kind === "external") {
    const text = String(data.label || data.title || "");
    return Math.max(170, Math.min(420, 140 + text.length * 5));
  }

  const lines = Array.isArray(data.instructions) ? data.instructions : [];
  let longest = 0;
  for (const line of lines) {
    const tokens = Array.isArray(line && line.tokens) ? line.tokens : [];
    const str = tokens.map((t) => String((t && t.text) || "")).join("");
    longest = Math.max(longest, str.length);
  }
  if (!lines.length) longest = Math.max(longest, String(data.title || data.label || "").length);
  return Math.max(180, Math.min(560, 160 + longest * 6.5));
}

function estimateNodeHeight(node) {
  const data = node && node.data ? node.data : {};
  if (data.node_kind === "group") return 70;
  if (data.node_kind === "external") return 62;

  const lines = Array.isArray(data.instructions) ? data.instructions.length : 0;
  const truncated = Number(data.preview_truncated) || 0;
  const base = 28;
  const lineH = 15;
  const extra = truncated > 0 ? 18 : 0;
  const padding = 12;
  return Math.max(64, Math.min(260, base + padding + Math.max(1, lines) * lineH + extra));
}

function nodeHtml(data) {
  const nodeKind = data && data.node_kind ? data.node_kind : "block";
  const nodeClasses = String((data && data.node_classes) || "");
  const classes = ["node-html"];

  if (nodeKind === "external") classes.push("node-external");
  if (nodeClasses.includes("entry")) classes.push("node-entry");

  const inlineStyle = `width:${data.render_width}px; height:${data.render_height}px;`;
  const rva = data && data.rva ? data.rva : "-";
  const count = Number(data && data.instruction_count) || 0;
  const lines = Array.isArray(data && data.instructions) ? data.instructions : [];
  const truncated = Number(data && data.preview_truncated) || 0;

  let body = "";
  if (!lines.length) {
    body = `<div class="node-line"><span class="node-lineno">--</span><span>${escapeHtml(
      data && data.title ? data.title : data && data.label ? data.label : "nœud"
    )}</span></div>`;
  } else {
    body = lines.map((l, i) => lineHtml(l, i)).join("");
    if (truncated > 0) {
      body += `<div class="node-more">... +${truncated} instructions</div>`;
    }
  }

  return (
    `<div class="${classes.join(" ")}" style="${inlineStyle}">` +
    `<div class="node-head"><span><i class="ph ph-hash"></i> ${escapeHtml(rva)}</span><span>${count} <i class="ph ph-cpu"></i></span></div>` +
    `<div class="node-body">${body}</div>` +
    "</div>"
  );
}

function normalizeGraphElements(func) {
  const elements = (func && func.elements) || {};
  const rawNodes = Array.isArray(elements.nodes) ? elements.nodes : [];
  const rawEdges = Array.isArray(elements.edges) ? elements.edges : [];

  const nodes = rawNodes.map((node) => {
    const clone = JSON.parse(JSON.stringify(node));
    if (!clone.data) clone.data = {};
    clone.data.node_classes = clone.classes || "";
    clone.data.render_width = estimateNodeWidth(clone);
    clone.data.render_height = estimateNodeHeight(clone);
    clone.data.fallback_label = buildFallbackLabel(clone.data);
    return clone;
  });

  const edges = rawEdges.map((edge) => JSON.parse(JSON.stringify(edge)));
  return { nodes, edges };
}

function getLeftFunctions() {
  if (!state.leftPayload || !Array.isArray(state.leftPayload.functions)) return [];
  return state.leftPayload.functions;
}

function getRightFunctions() {
  if (!state.rightPayload || !Array.isArray(state.rightPayload.functions)) return [];
  return state.rightPayload.functions;
}

function getSelectedLeftFunction() {
  return getLeftFunctions().find((f) => f.id === state.selectedLeftId) || null;
}

function initCy(side) {
  if (state.cy[side]) return state.cy[side];

  const container = side === "left" ? dom.cyLeft : dom.cyRight;
  const cy = cytoscape({
    container,
    elements: [],
    style: graphStyle(),
    wheelSensitivity: 0.2,
    boxSelectionEnabled: false,
  });

  if (typeof cy.nodeHtmlLabel === "function") {
    cy.nodeHtmlLabel([
      {
        query: "node",
        halign: "center",
        valign: "center",
        tpl: (data) => nodeHtml(data),
      },
    ], {
      enablePointerEvents: true,
    });
  } else {
    cy.style()
      .selector("node")
      .style({
        label: "data(fallback_label)",
        "text-wrap": "wrap",
        "text-max-width": 440,
        "text-valign": "center",
        "text-halign": "center",
      })
      .update();
  }

  cy.on("tap", "node", (evt) => {
    const targetFnId = evt.target.data("target_function_id");
    if (!targetFnId || !state.indexes) return;
    if (side === "left") {
      if (state.indexes.leftById.has(targetFnId)) {
        state.selectedLeftId = targetFnId;
        renderEverything();
      }
      return;
    }
    const mappedLeftId = state.indexes.rightToLeftById.get(targetFnId);
    if (mappedLeftId) {
      state.selectedLeftId = mappedLeftId;
      renderEverything();
    }
  });

  state.cy[side] = cy;
  return cy;
}

function applyLayout(side) {
  const cy = initCy(side);
  cy.layout(layoutOptions()).run();
}

function renderGraph(side, func) {
  const cy = initCy(side);
  cy.elements().remove();
  if (!func) return;

  const normalized = normalizeGraphElements(func);
  cy.add(normalized.nodes);
  cy.add(normalized.edges);
  applyLayout(side);
}

function buildIndexes() {
  const leftFunctions = getLeftFunctions();
  const rightFunctions = getRightFunctions();

  const rightById = new Map();
  const rightByRva = new Map();
  const rightByName = new Map();

  for (const fn of rightFunctions) {
    rightById.set(fn.id, fn);
    const rva = parseHexNumber(fn.rva);
    if (rva !== null) rightByRva.set(rva, fn);
    const key = normName(fn.name);
    if (!rightByName.has(key)) rightByName.set(key, []);
    rightByName.get(key).push(fn);
  }

  const mapFunctions = Array.isArray(state.mapPayload && state.mapPayload.functions)
    ? state.mapPayload.functions
    : [];
  const mapBlocks = Array.isArray(state.mapPayload && state.mapPayload.blocks)
    ? state.mapPayload.blocks
    : [];

  const mapByOldRva = new Map();
  const mapByName = new Map();
  for (const entry of mapFunctions) {
    const oldRva = coerceNumber(entry && entry.old_rva);
    if (oldRva !== null) mapByOldRva.set(oldRva, entry);
    const key = normName(entry && entry.name);
    if (!mapByName.has(key)) mapByName.set(key, []);
    mapByName.get(key).push(entry);
  }

  const mapBlocksByFunctionName = new Map();
  for (const block of mapBlocks) {
    const key = normName(block && block.function_name);
    if (!mapBlocksByFunctionName.has(key)) mapBlocksByFunctionName.set(key, []);
    mapBlocksByFunctionName.get(key).push(block);
  }

  const indexes = {
    rightById,
    rightByRva,
    rightByName,
    mapByOldRva,
    mapByName,
    mapBlocksByFunctionName,
    leftById: new Map(leftFunctions.map((fn) => [fn.id, fn])),
    leftToMapping: new Map(),
    rightToLeftById: new Map(),
  };

  for (const leftFn of leftFunctions) {
    const mapping = resolveRightForLeft(leftFn, indexes);
    indexes.leftToMapping.set(leftFn.id, mapping);
    if (mapping.rightFn) {
      indexes.rightToLeftById.set(mapping.rightFn.id, leftFn.id);
    }
  }

  state.indexes = indexes;
}

function resolveRightForLeft(leftFn, indexes) {
  const out = {
    leftRva: parseHexNumber(leftFn && leftFn.rva),
    mapEntry: null,
    rightFn: null,
    comparableBlocks: 0,
    changedBlocks: 0,
    reason: "none",
  };

  if (!leftFn) return out;

  const key = normName(leftFn.name);
  if (out.leftRva !== null && indexes.mapByOldRva.has(out.leftRva)) {
    out.mapEntry = indexes.mapByOldRva.get(out.leftRva);
  }

  if (!out.mapEntry) {
    const byName = indexes.mapByName.get(key) || [];
    if (byName.length === 1) out.mapEntry = byName[0];
  }

  if (out.mapEntry) {
    const newRva = coerceNumber(out.mapEntry && out.mapEntry.new_rva);
    if (newRva !== null && indexes.rightByRva.has(newRva)) {
      out.rightFn = indexes.rightByRva.get(newRva);
      out.reason = "map-rva";
    }
  }

  if (!out.rightFn) {
    const candidates = indexes.rightByName.get(key) || [];
    if (candidates.length === 1) {
      out.rightFn = candidates[0];
      out.reason = "name";
    }
  }

  const leftBlocksByRva = new Map();
  const leftNodes = Array.isArray(leftFn?.elements?.nodes) ? leftFn.elements.nodes : [];
  for (const node of leftNodes) {
    if (!node || !node.data || node.data.node_kind !== "block") continue;
    const rva = parseHexNumber(node.data.rva);
    if (rva === null) continue;
    leftBlocksByRva.set(rva, coerceNumber(node.data.size_bytes) || 0);
  }

  const blockKey = normName((out.mapEntry && out.mapEntry.name) || leftFn.name);
  const blocks = indexes.mapBlocksByFunctionName.get(blockKey) || [];
  for (const block of blocks) {
    const oldRva = coerceNumber(block && block.old_rva);
    if (oldRva === null || !leftBlocksByRva.has(oldRva)) continue;
    const oldSize = leftBlocksByRva.get(oldRva);
    const newSize = coerceNumber(block && block.encoded_size);
    if (newSize === null) continue;
    out.comparableBlocks += 1;
    if (oldSize !== newSize) out.changedBlocks += 1;
  }

  return out;
}

function getSelectedMapping() {
  if (!state.indexes) return null;
  return state.indexes.leftToMapping.get(state.selectedLeftId) || null;
}

function setHeaderSummary(leftFn, mapping) {
  if (!leftFn) {
    dom.selectedFnName.textContent = "-";
    dom.selectedOldAddr.textContent = "-";
    dom.selectedNewAddr.textContent = "-";
    dom.selectedMutation.textContent = "-";
    dom.selectedFallback.textContent = "-";
    return;
  }

  dom.selectedFnName.textContent = leftFn.name || "-";
  dom.selectedOldAddr.textContent = leftFn.address || leftFn.rva || "-";

  let mappedAddr = "-";
  if (mapping && mapping.rightFn && mapping.rightFn.address) {
    mappedAddr = mapping.rightFn.address;
  } else if (mapping && mapping.mapEntry) {
    const imageBase = coerceNumber(state.mapPayload && state.mapPayload.image_base);
    const newRva = coerceNumber(mapping.mapEntry.new_rva);
    if (imageBase !== null && newRva !== null) {
      mappedAddr = formatHex(imageBase + newRva);
    } else if (newRva !== null) {
      mappedAddr = formatHex(newRva);
    }
  }
  dom.selectedNewAddr.textContent = mappedAddr;

  if (mapping && mapping.comparableBlocks > 0) {
    dom.selectedMutation.textContent = `${mapping.changedBlocks}/${mapping.comparableBlocks}`;
  } else if (mapping && mapping.mapEntry) {
    dom.selectedMutation.textContent = "indéterminé";
  } else {
    dom.selectedMutation.textContent = "non mappée";
  }

  const fallback = mapping && mapping.mapEntry && typeof mapping.mapEntry.fallback === "boolean"
    ? (mapping.mapEntry.fallback ? "oui" : "non")
    : "-";
  dom.selectedFallback.textContent = fallback;
}

function setGraphMeta(leftFn, rightFn) {
  if (!leftFn) {
    dom.leftFnMeta.textContent = "-";
  } else {
    dom.leftFnMeta.textContent = `${leftFn.address || "-"} | rva=${leftFn.rva || "-"} | instr=${leftFn.instruction_count || 0} | edges=${leftFn.edge_count || 0} | refs=${leftFn.refs_to_function || 0}`;
  }

  if (!rightFn) {
    dom.rightFnMeta.textContent = "pas de correspondance";
  } else {
    dom.rightFnMeta.textContent = `${rightFn.address || "-"} | rva=${rightFn.rva || "-"} | instr=${rightFn.instruction_count || 0} | edges=${rightFn.edge_count || 0} | refs=${rightFn.refs_to_function || 0}`;
  }
}

function renderPassInfo() {
  if (!state.mapPayload) {
    dom.passProfile.textContent = "-";
    dom.passSeed.textContent = "-";
    dom.rewrittenBytes.textContent = "-";
    dom.passList.innerHTML = '<span class="pass-chip">map non chargée</span>';
    dom.passStatsBody.innerHTML = "";
    return;
  }

  dom.passProfile.textContent = String(state.mapPayload.obfuscation_profile || "-");
  dom.passSeed.textContent = String(state.mapPayload.obfuscation_seed ?? "-");
  dom.rewrittenBytes.textContent = String(state.mapPayload.rewritten_bytes ?? "-");

  const applied = Array.isArray(state.mapPayload.applied_passes) ? state.mapPayload.applied_passes : [];
  if (!applied.length) {
    dom.passList.innerHTML = '<span class="pass-chip">aucune</span>';
  } else {
    dom.passList.innerHTML = applied
      .map((p) => `<span class="pass-chip">${escapeHtml(String(p))}</span>`)
      .join("");
  }

  const stats = Array.isArray(state.mapPayload.pass_stats) ? state.mapPayload.pass_stats : [];
  dom.passStatsBody.innerHTML = stats
    .map((row) => {
      const name = escapeHtml(String(row && row.name ? row.name : "-"));
      const mf = escapeHtml(String(row && row.mutated_functions != null ? row.mutated_functions : "-"));
      const mb = escapeHtml(String(row && row.mutated_blocks != null ? row.mutated_blocks : "-"));
      const mi = escapeHtml(String(row && row.mutated_instructions != null ? row.mutated_instructions : "-"));
      const ib = escapeHtml(String(row && row.injected_blocks != null ? row.injected_blocks : "-"));
      const ss = escapeHtml(String(row && row.skipped_sites != null ? row.skipped_sites : "-"));
      return `<tr><td>${name}</td><td>${mf}</td><td>${mb}</td><td>${mi}</td><td>${ib}</td><td>${ss}</td></tr>`;
    })
    .join("");
}

function filterLeftFunctions() {
  const query = dom.searchInput.value.trim().toLowerCase();
  const all = getLeftFunctions();

  state.filteredLeftFunctions = all.filter((func) => {
    if (!query) return true;
    return (
      String(func.name || "").toLowerCase().includes(query)
      || String(func.address || "").toLowerCase().includes(query)
      || String(func.rva || "").toLowerCase().includes(query)
    );
  });

  if (state.sortByNameAsc) {
    state.filteredLeftFunctions.sort((a, b) => String(a.name || "").localeCompare(String(b.name || "")));
  }

  if (!state.filteredLeftFunctions.some((f) => f.id === state.selectedLeftId)) {
    state.selectedLeftId = state.filteredLeftFunctions.length ? state.filteredLeftFunctions[0].id : null;
  }
}

function renderFunctionList() {
  const all = getLeftFunctions();
  dom.functionList.innerHTML = "";

  for (const func of state.filteredLeftFunctions) {
    const mapping = state.indexes ? state.indexes.leftToMapping.get(func.id) : null;
    const hasMutation = Boolean(mapping && mapping.changedBlocks > 0);
    const item = document.createElement("button");
    item.type = "button";
    item.className = `fn-item${state.selectedLeftId === func.id ? " active" : ""}${hasMutation ? " mutated" : ""}`;

    const rightRva = (mapping && mapping.rightFn && mapping.rightFn.rva)
      || (mapping && mapping.mapEntry && mapping.mapEntry.new_rva != null ? formatHex(mapping.mapEntry.new_rva) : "-");

    const diff = mapping
      ? `old=${escapeHtml(String(func.rva || "-"))} -> new=${escapeHtml(String(rightRva || "-"))}`
      : "sans correspondance à droite";

    item.innerHTML = `
      <div class="fn-item-title"><i class="ph ph-function"></i> ${escapeHtml(func.name || "-")}</div>
      <div class="fn-item-meta">
        <span>${escapeHtml(String(func.address || "-"))}</span>
        <span>refs:${escapeHtml(String(func.refs_to_function || 0))}</span>
        <span>instr:${escapeHtml(String(func.instruction_count || 0))}</span>
      </div>
      <div class="fn-item-diff">${diff}</div>
    `;

    item.addEventListener("click", () => {
      state.selectedLeftId = func.id;
      renderEverything();
    });

    dom.functionList.appendChild(item);
  }

  dom.listStats.innerHTML = `<i class="ph ph-list-numbers"></i> ${state.filteredLeftFunctions.length} sur ${all.length}`;
}

function renderEverything() {
  filterLeftFunctions();
  renderFunctionList();
  renderPassInfo();

  const leftFn = getSelectedLeftFunction();
  const mapping = getSelectedMapping();
  const rightFn = mapping && mapping.rightFn ? mapping.rightFn : null;

  setHeaderSummary(leftFn, mapping);
  setGraphMeta(leftFn, rightFn);

  renderGraph("left", leftFn);
  renderGraph("right", rightFn);
}

function setComparePayloads(leftPayload, rightPayload, mapPayload, paths = {}) {
  state.leftPayload = leftPayload;
  state.rightPayload = rightPayload;
  state.mapPayload = mapPayload || null;

  if (paths.leftPath) dom.leftJsonPathInput.value = paths.leftPath;
  if (paths.rightPath) dom.rightJsonPathInput.value = paths.rightPath;
  if (paths.mapPath) dom.mapJsonPathInput.value = paths.mapPath;

  const leftFunctions = Array.isArray(leftPayload && leftPayload.functions) ? leftPayload.functions : [];
  const preferred = leftPayload && leftPayload.meta && leftPayload.meta.selected_function_id;

  if (preferred && leftFunctions.some((f) => f.id === preferred)) {
    state.selectedLeftId = preferred;
  } else {
    state.selectedLeftId = leftFunctions.length ? leftFunctions[0].id : null;
  }

  buildIndexes();
  renderEverything();
}

async function fetchJsonDirect(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} lors du chargement de '${path}'`);
  }
  return response.json();
}

async function apiCall(url, options = {}) {
  try {
    const response = await fetch(url, options);
    return response;
  } catch (_) {
    return null;
  }
}

async function loadCompareFromApiPaths(leftPath, rightPath, mapPath) {
  const response = await apiCall("/api/load-compare", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ leftPath, rightPath, mapPath }),
  });
  if (!response) return false;
  if (response.status === 404 || response.status === 405) return false;
  if (!response.ok) {
    const body = await response.text();
    throw new Error(body || `API /api/load-compare: HTTP ${response.status}`);
  }
  const payload = await response.json();
  setComparePayloads(payload.leftPayload, payload.rightPayload, payload.mapPayload || null, {
    leftPath: payload.leftPath || leftPath,
    rightPath: payload.rightPath || rightPath,
    mapPath: payload.mapPath || mapPath || "",
  });
  return true;
}

async function loadCompareFromPaths(leftPath, rightPath, mapPath) {
  const triedApi = await loadCompareFromApiPaths(leftPath, rightPath, mapPath).catch((err) => {
    throw err;
  });
  if (triedApi) return;

  const [leftPayload, rightPayload, mapPayload] = await Promise.all([
    fetchJsonDirect(leftPath),
    fetchJsonDirect(rightPath),
    mapPath ? fetchJsonDirect(mapPath) : Promise.resolve(null),
  ]);
  setComparePayloads(leftPayload, rightPayload, mapPayload, { leftPath, rightPath, mapPath: mapPath || "" });
}

async function loadLastRun() {
  const response = await apiCall("/api/last-run", { cache: "no-store" });
  if (!response || response.status === 404) return false;
  if (!response.ok) {
    const body = await response.text();
    throw new Error(body || `API /api/last-run: HTTP ${response.status}`);
  }
  const payload = await response.json();
  setComparePayloads(payload.leftPayload, payload.rightPayload, payload.mapPayload || null, {
    leftPath: payload.leftPath || "",
    rightPath: payload.rightPath || "",
    mapPath: payload.mapPath || "",
  });
  return true;
}

async function loadConfigDefaults() {
  const response = await apiCall("/api/config", { cache: "no-store" });
  if (!response || !response.ok) return;
  const cfg = await response.json();

  if (!dom.exePathInput.value && cfg.defaultInputExe) dom.exePathInput.value = cfg.defaultInputExe;
  if (!dom.cfgPathInput.value && cfg.defaultCfgJson) dom.cfgPathInput.value = cfg.defaultCfgJson;

  if (!dom.leftJsonPathInput.value && cfg.lastLeftPath) dom.leftJsonPathInput.value = cfg.lastLeftPath;
  if (!dom.rightJsonPathInput.value && cfg.lastRightPath) dom.rightJsonPathInput.value = cfg.lastRightPath;
  if (!dom.mapJsonPathInput.value && cfg.lastMapPath) dom.mapJsonPathInput.value = cfg.lastMapPath;
}

async function runObfuscationFromForm() {
  const inputExe = dom.exePathInput.value.trim();
  const cfgJson = dom.cfgPathInput.value.trim();
  if (!inputExe || !cfgJson) {
    throw new Error("EXE input et CFG input sont obligatoires");
  }

  const seedRaw = dom.seedInput.value.trim();
  const seed = seedRaw ? Number.parseInt(seedRaw, 10) : null;

  const body = {
    inputExe,
    cfgJson,
    profile: dom.profileSelect.value,
    strictUnwind: Boolean(dom.strictUnwindInput.checked),
    rewritePolicy: dom.rewritePolicySelect.value,
    sectionLayout: dom.sectionLayoutSelect.value,
  };
  if (Number.isFinite(seed)) body.seed = seed;

  const response = await apiCall("/api/run-obfuscation", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!response) {
    throw new Error("API backend non disponible. Lance le viewer via server.js");
  }
  if (!response.ok) {
    const txt = await response.text();
    throw new Error(txt || `API /api/run-obfuscation: HTTP ${response.status}`);
  }

  const payload = await response.json();
  setComparePayloads(payload.leftPayload, payload.rightPayload, payload.mapPayload || null, {
    leftPath: payload.leftPath || "",
    rightPath: payload.rightPath || "",
    mapPath: payload.mapPath || "",
  });
}

function handleGraphToolClick(evt) {
  const btn = evt.currentTarget;
  const side = btn.dataset.side;
  const action = btn.dataset.action;
  const cy = initCy(side);
  if (!cy) return;

  if (action === "zoomIn") {
    cy.zoom({ level: cy.zoom() * 1.2, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
    return;
  }
  if (action === "zoomOut") {
    cy.zoom({ level: cy.zoom() / 1.2, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
    return;
  }
  if (action === "fit") {
    cy.fit(undefined, 28);
    return;
  }
  if (action === "layout") {
    applyLayout(side);
  }
}

async function bootstrap() {
  setStatus("idle", "chargement...");

  const query = new URLSearchParams(window.location.search);
  if (query.get("exe")) dom.exePathInput.value = query.get("exe");
  if (query.get("cfg")) dom.cfgPathInput.value = query.get("cfg");
  if (query.get("profile")) dom.profileSelect.value = query.get("profile");
  if (query.get("seed")) dom.seedInput.value = query.get("seed");

  await loadConfigDefaults();

  const leftQ = query.get("left");
  const rightQ = query.get("right");
  const mapQ = query.get("map");

  try {
    if (leftQ && rightQ) {
      await loadCompareFromPaths(leftQ, rightQ, mapQ || "");
      setStatus("ok", "comparaison chargée");
      return;
    }

    if (await loadLastRun()) {
      setStatus("ok", "dernier run chargé");
      return;
    }

    const fallback = query.get("cy") || "cfg_output.json";
    await loadCompareFromPaths(fallback, fallback, mapQ || "");
    setStatus("ok", "json chargé");
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    setStatus("error", "erreur");
    dom.listStats.innerHTML = `<i class="ph ph-warning"></i> ${escapeHtml(message)}`;
  }
}

dom.searchInput.addEventListener("input", () => renderEverything());

dom.sortBtn.addEventListener("click", () => {
  state.sortByNameAsc = !state.sortByNameAsc;
  dom.sortBtn.innerHTML = state.sortByNameAsc
    ? '<i class="ph ph-sort-descending"></i>'
    : '<i class="ph ph-sort-ascending"></i>';
  renderEverything();
});

dom.graphTools.forEach((btn) => {
  btn.addEventListener("click", handleGraphToolClick);
});

dom.loadCompareBtn.addEventListener("click", async () => {
  const leftPath = dom.leftJsonPathInput.value.trim();
  const rightPath = dom.rightJsonPathInput.value.trim();
  const mapPath = dom.mapJsonPathInput.value.trim();

  if (!leftPath || !rightPath) {
    setStatus("error", "left/right requis");
    return;
  }

  try {
    setStatus("running", "chargement comparaison...");
    await loadCompareFromPaths(leftPath, rightPath, mapPath);
    setStatus("ok", "comparaison chargée");
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    setStatus("error", "échec chargement");
    dom.listStats.innerHTML = `<i class="ph ph-warning"></i> ${escapeHtml(message)}`;
  }
});

dom.loadLastBtn.addEventListener("click", async () => {
  try {
    setStatus("running", "chargement dernier run...");
    const loaded = await loadLastRun();
    if (!loaded) {
      setStatus("error", "aucun dernier run");
      return;
    }
    setStatus("ok", "dernier run chargé");
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    setStatus("error", "échec dernier run");
    dom.listStats.innerHTML = `<i class="ph ph-warning"></i> ${escapeHtml(message)}`;
  }
});

dom.runObfBtn.addEventListener("click", async () => {
  if (state.running) return;
  state.running = true;
  dom.runObfBtn.disabled = true;
  try {
    setStatus("running", "obfuscation en cours...");
    await runObfuscationFromForm();
    setStatus("ok", "obfuscation terminée");
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    setStatus("error", "obfuscation échouée");
    dom.listStats.innerHTML = `<i class="ph ph-warning"></i> ${escapeHtml(message)}`;
  } finally {
    state.running = false;
    dom.runObfBtn.disabled = false;
  }
});

dom.togglePanelsBtn.addEventListener("click", () => {
  const compact = !document.body.classList.contains("compact-panels");
  setCompactPanels(compact);
});

initCompactPanels();
bootstrap();
