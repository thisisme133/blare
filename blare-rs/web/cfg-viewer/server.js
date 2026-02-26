#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const { spawn } = require("node:child_process");

const VIEWER_ROOT = __dirname;
const PROJECT_ROOT = process.env.BLARE_ROOT
  ? path.resolve(process.env.BLARE_ROOT)
  : path.resolve(__dirname, "../..");
const PORT = Number.parseInt(process.env.CFG_VIEWER_PORT || "8080", 10);
const LAST_RUN_FILE = path.join(VIEWER_ROOT, ".last_compare.json");

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function sendText(res, statusCode, text) {
  res.writeHead(statusCode, {
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(text);
}

function normalizeUserPath(raw, baseDir = VIEWER_ROOT) {
  if (typeof raw !== "string" || !raw.trim()) {
    throw new Error("path manquant");
  }
  const trimmed = raw.trim();
  if (path.isAbsolute(trimmed)) return path.normalize(trimmed);
  return path.resolve(baseDir, trimmed);
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

async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw);
  } catch (_) {
    throw new Error("JSON body invalide");
  }
}

async function readJsonFile(filePath) {
  const raw = await fsp.readFile(filePath, "utf8");
  return JSON.parse(raw);
}

async function runCommand(cmd, args, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });

    child.on("error", (err) => {
      reject(err);
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        const error = new Error(`commande échouée (${cmd}): code ${code}`);
        error.stdout = stdout;
        error.stderr = stderr;
        error.code = code;
        reject(error);
      }
    });
  });
}

function tailText(value, maxChars = 8000) {
  const text = String(value || "");
  if (text.length <= maxChars) return text;
  return text.slice(text.length - maxChars);
}

function ensurePayloadShape(payload, label) {
  if (!payload || !Array.isArray(payload.functions)) {
    throw new Error(`${label}: format invalide (functions[] manquant)`);
  }
}

async function loadComparePayloads(leftPathRaw, rightPathRaw, mapPathRaw) {
  const leftPath = normalizeUserPath(leftPathRaw);
  const rightPath = normalizeUserPath(rightPathRaw);
  const mapPath = mapPathRaw ? normalizeUserPath(mapPathRaw) : "";

  const leftPayload = await readJsonFile(leftPath);
  const rightPayload = await readJsonFile(rightPath);
  const mapPayload = mapPath ? await readJsonFile(mapPath) : null;

  ensurePayloadShape(leftPayload, "left json");
  ensurePayloadShape(rightPayload, "right json");

  return {
    leftPath,
    rightPath,
    mapPath,
    leftPayload,
    rightPayload,
    mapPayload,
  };
}

function remapCfgWithMap(cfg, mapPayload) {
  const out = JSON.parse(JSON.stringify(cfg));
  const imageBase = coerceNumber(out && out.image_base);
  if (imageBase === null) {
    throw new Error("cfg.image_base invalide");
  }

  const functionMap = new Map();
  const functionByOldRva = new Map();
  const mapFunctions = Array.isArray(mapPayload && mapPayload.functions) ? mapPayload.functions : [];
  for (const entry of mapFunctions) {
    const oldRva = coerceNumber(entry && entry.old_rva);
    const newRva = coerceNumber(entry && entry.new_rva);
    if (oldRva === null || newRva === null) continue;
    const oldAddr = imageBase + oldRva;
    const newAddr = imageBase + newRva;
    functionMap.set(oldAddr, newAddr);
    functionByOldRva.set(oldRva, entry);
  }

  const blockMap = new Map();
  const mapBlocks = Array.isArray(mapPayload && mapPayload.blocks) ? mapPayload.blocks : [];
  for (const block of mapBlocks) {
    const oldRva = coerceNumber(block && block.old_rva);
    const newRva = coerceNumber(block && block.new_rva);
    const encodedSize = Math.max(1, coerceNumber(block && block.encoded_size) || 1);
    if (oldRva === null || newRva === null) continue;
    const oldAddr = imageBase + oldRva;
    const newAddr = imageBase + newRva;
    blockMap.set(oldAddr, { start: newAddr, end: newAddr + encodedSize });
  }

  const toHexAddress = (n) => `0x${n.toString(16)}`;

  const remapAddressNumber = (value) => {
    const n = coerceNumber(value);
    if (n === null) return null;
    if (functionMap.has(n)) return functionMap.get(n);
    if (blockMap.has(n)) return blockMap.get(n).start;
    return n;
  };

  const remapAddress = (value) => {
    const n = remapAddressNumber(value);
    if (n === null) return value;
    return toHexAddress(n);
  };

  for (const func of Array.isArray(out.functions) ? out.functions : []) {
    const originalFnAddr = coerceNumber(func.address);
    const originalFnRva = originalFnAddr === null ? null : originalFnAddr - imageBase;
    const mappedFn = originalFnRva !== null ? functionByOldRva.get(originalFnRva) : null;

    if (mappedFn) {
      const newRva = coerceNumber(mappedFn.new_rva);
      if (newRva !== null) func.address = toHexAddress(imageBase + newRva);
    } else if (originalFnAddr !== null && functionMap.has(originalFnAddr)) {
      func.address = toHexAddress(functionMap.get(originalFnAddr));
    }

    const newFnAddr = coerceNumber(func.address);

    for (const block of Array.isArray(func.blocks) ? func.blocks : []) {
      const oldStart = coerceNumber(block.start);
      const oldEnd = coerceNumber(block.end);
      if (oldStart !== null && blockMap.has(oldStart)) {
        const mapped = blockMap.get(oldStart);
        block.start = toHexAddress(mapped.start);
        block.end = toHexAddress(mapped.end);
        continue;
      }

      if (
        mappedFn
        && newFnAddr !== null
        && originalFnAddr !== null
        && oldStart !== null
      ) {
        const delta = oldStart - originalFnAddr;
        const oldLen = oldEnd !== null && oldEnd > oldStart ? oldEnd - oldStart : 1;
        const newStart = newFnAddr + delta;
        block.start = toHexAddress(newStart);
        block.end = toHexAddress(newStart + Math.max(1, oldLen));
        continue;
      }

      block.start = remapAddress(block.start);
      block.end = remapAddress(block.end);
    }

    for (const edge of Array.isArray(func.edges) ? func.edges : []) {
      edge.from = remapAddress(edge.from);
      edge.to = remapAddress(edge.to);
    }

    for (const site of Array.isArray(func.indirect_call_sites) ? func.indirect_call_sites : []) {
      if (site && typeof site === "object") {
        site.address = remapAddress(site.address);
        if (Array.isArray(site.possible_targets)) {
          site.possible_targets = site.possible_targets.map((addr) => remapAddress(addr));
        }
      }
    }

    for (const site of Array.isArray(func.indirect_sites) ? func.indirect_sites : []) {
      if (site && typeof site === "object") {
        site.address = remapAddress(site.address);
        if (Array.isArray(site.possible_targets)) {
          site.possible_targets = site.possible_targets.map((addr) => remapAddress(addr));
        }
      }
    }

    for (const table of Array.isArray(func.jump_tables) ? func.jump_tables : []) {
      if (table && typeof table === "object") {
        table.site = remapAddress(table.site);
        if (Array.isArray(table.targets)) {
          table.targets = table.targets.map((addr) => remapAddress(addr));
        }
      }
    }
  }

  return out;
}

async function readLastRunPaths() {
  try {
    const data = await readJsonFile(LAST_RUN_FILE);
    return data;
  } catch (_) {
    return null;
  }
}

async function writeLastRunPaths(data) {
  const payload = {
    saved_at: new Date().toISOString(),
    ...data,
  };
  await fsp.writeFile(LAST_RUN_FILE, JSON.stringify(payload, null, 2), "utf8");
}

function firstExisting(candidates) {
  for (const p of candidates) {
    if (!p) continue;
    try {
      if (fs.existsSync(p)) return p;
    } catch (_) {
      // ignore
    }
  }
  return "";
}

async function handleApiConfig(res) {
  const last = await readLastRunPaths();
  const defaultInputExe = firstExisting([
    process.env.CFG_VIEWER_INPUT_EXE || "",
    "/private/tmp/imgui_dx9_x64_demo.exe",
    "/tmp/imgui_dx9_x64_demo.exe",
  ]);
  const defaultCfgJson = firstExisting([
    process.env.CFG_VIEWER_CFG_JSON || "",
    "/private/tmp/imgui_dx9_x64_demo.ghidra.json",
    "/tmp/imgui_dx9_x64_demo.ghidra.json",
    path.join(VIEWER_ROOT, "cfg_output.json"),
  ]);

  sendJson(res, 200, {
    projectRoot: PROJECT_ROOT,
    defaultInputExe,
    defaultCfgJson,
    lastLeftPath: last && last.leftPath ? last.leftPath : "",
    lastRightPath: last && last.rightPath ? last.rightPath : "",
    lastMapPath: last && last.mapPath ? last.mapPath : "",
  });
}

async function handleApiLoadCompare(req, res) {
  const body = await readJsonBody(req);
  const leftPath = body.leftPath;
  const rightPath = body.rightPath;
  const mapPath = body.mapPath || "";

  if (!leftPath || !rightPath) {
    sendText(res, 400, "leftPath et rightPath sont requis");
    return;
  }

  const payload = await loadComparePayloads(leftPath, rightPath, mapPath);
  sendJson(res, 200, payload);
}

async function handleApiLastRun(res) {
  const last = await readLastRunPaths();
  if (!last || !last.leftPath || !last.rightPath) {
    sendText(res, 404, "no last run");
    return;
  }

  const payload = await loadComparePayloads(last.leftPath, last.rightPath, last.mapPath || "");
  sendJson(res, 200, payload);
}

async function handleApiRunObfuscation(req, res) {
  const body = await readJsonBody(req);

  const inputExe = normalizeUserPath(body.inputExe);
  const cfgJson = normalizeUserPath(body.cfgJson);
  const profile = typeof body.profile === "string" ? body.profile.trim() || "balanced" : "balanced";
  const seed = coerceNumber(body.seed);
  const strictUnwind = body.strictUnwind !== false;
  const rewritePolicy = body.rewritePolicy === "per-function" ? "per-function" : "module";
  const sectionLayout = body.sectionLayout === "compact" ? "compact" : "keep";

  const outputDir = body.outputDir
    ? normalizeUserPath(body.outputDir, process.cwd())
    : "/private/tmp";
  await fsp.mkdir(outputDir, { recursive: true });

  const baseName = path.basename(inputExe, path.extname(inputExe));
  const stamp = `${Date.now()}`;
  const prefix = path.join(outputDir, `${baseName}.web.${profile}.${stamp}`);

  const outputExe = `${prefix}.exe`;
  const mapPath = `${prefix}.map.json`;
  const leftJson = `${prefix}.left.cytoscape.json`;
  const rewrittenCfgPath = `${prefix}.rewritten.cfg.json`;
  const rightJson = `${prefix}.right.cytoscape.json`;

  const rewriteArgs = [
    "run",
    "-p",
    "blare-cli",
    "--",
    "rewrite",
    "--input",
    inputExe,
    "--cfg",
    cfgJson,
    "--output",
    outputExe,
    "--map",
    mapPath,
    "--profile",
    profile,
    "--rewrite-policy",
    rewritePolicy,
    "--section-layout",
    sectionLayout,
  ];
  if (seed !== null) {
    rewriteArgs.push("--seed", String(seed));
  }
  if (strictUnwind) {
    rewriteArgs.push("--strict-unwind");
  }

  const exportLeftArgs = [
    "run",
    "-p",
    "blare-cli",
    "--",
    "export-cytoscape",
    "--input",
    inputExe,
    "--cfg",
    cfgJson,
    "--output",
    leftJson,
  ];

  let rewriteLog = null;
  let exportLeftLog = null;
  let exportRightLog = null;

  try {
    rewriteLog = await runCommand("cargo", rewriteArgs, PROJECT_ROOT);
    exportLeftLog = await runCommand("cargo", exportLeftArgs, PROJECT_ROOT);

    const cfgPayload = await readJsonFile(cfgJson);
    const mapPayload = await readJsonFile(mapPath);
    const rewrittenCfg = remapCfgWithMap(cfgPayload, mapPayload);
    await fsp.writeFile(rewrittenCfgPath, JSON.stringify(rewrittenCfg, null, 2), "utf8");

    const exportRightArgs = [
      "run",
      "-p",
      "blare-cli",
      "--",
      "export-cytoscape",
      "--input",
      outputExe,
      "--cfg",
      rewrittenCfgPath,
      "--output",
      rightJson,
    ];
    exportRightLog = await runCommand("cargo", exportRightArgs, PROJECT_ROOT);

    const payload = await loadComparePayloads(leftJson, rightJson, mapPath);

    await writeLastRunPaths({
      inputExe,
      cfgJson,
      outputExe,
      mapPath,
      leftPath: leftJson,
      rightPath: rightJson,
      rewrittenCfgPath,
      profile,
      seed,
      strictUnwind,
      rewritePolicy,
      sectionLayout,
    });

    sendJson(res, 200, {
      ...payload,
      outputExe,
      rewrittenCfgPath,
      runLogs: {
        rewrite: {
          stdout: tailText(rewriteLog && rewriteLog.stdout),
          stderr: tailText(rewriteLog && rewriteLog.stderr),
        },
        exportLeft: {
          stdout: tailText(exportLeftLog && exportLeftLog.stdout),
          stderr: tailText(exportLeftLog && exportLeftLog.stderr),
        },
        exportRight: {
          stdout: tailText(exportRightLog && exportRightLog.stdout),
          stderr: tailText(exportRightLog && exportRightLog.stderr),
        },
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const details = {
      message,
      stdout: tailText(err && err.stdout),
      stderr: tailText(err && err.stderr),
      inputExe,
      cfgJson,
      outputExe,
      mapPath,
      leftJson,
      rightJson,
      rewrittenCfgPath,
    };
    sendJson(res, 500, details);
  }
}

async function serveStatic(req, res, pathname) {
  let cleanPath = pathname;
  if (cleanPath === "/") cleanPath = "/index.html";

  const targetPath = path.resolve(VIEWER_ROOT, `.${cleanPath}`);
  if (!targetPath.startsWith(VIEWER_ROOT)) {
    sendText(res, 403, "forbidden");
    return;
  }

  let stat;
  try {
    stat = await fsp.stat(targetPath);
  } catch (_) {
    sendText(res, 404, "not found");
    return;
  }

  if (stat.isDirectory()) {
    const indexPath = path.join(targetPath, "index.html");
    try {
      const content = await fsp.readFile(indexPath);
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
      });
      res.end(content);
      return;
    } catch (_) {
      sendText(res, 404, "not found");
      return;
    }
  }

  const ext = path.extname(targetPath).toLowerCase();
  const mime = MIME_TYPES[ext] || "application/octet-stream";
  const content = await fsp.readFile(targetPath);
  res.writeHead(200, {
    "Content-Type": mime,
    "Cache-Control": "no-store",
  });
  res.end(content);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "127.0.0.1"}`);

  try {
    if (req.method === "GET" && url.pathname === "/api/config") {
      await handleApiConfig(res);
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/last-run") {
      await handleApiLastRun(res);
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/load-compare") {
      await handleApiLoadCompare(req, res);
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/run-obfuscation") {
      await handleApiRunObfuscation(req, res);
      return;
    }

    await serveStatic(req, res, url.pathname);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    sendJson(res, 500, { error: message });
  }
});

server.listen(PORT, () => {
  console.log(`cfg-viewer server running on http://127.0.0.1:${PORT}`);
  console.log(`project root: ${PROJECT_ROOT}`);
});
