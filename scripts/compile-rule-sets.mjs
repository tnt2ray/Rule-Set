#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { compileActionRuleSet, createActionAsnResolver, actionsArtifactDirectory, actionsArtifactPath, actionsOutputKey, ACTIONS_COMPILER_PROTOCOL, ACTIONS_OUTPUT_BRANCH, ACTIONS_CLIENT_DIRECTORIES } from "./actions-compiler-runtime.mjs";

// Keep this version aligned with src/vendor/singbox. The checksum is the official
// release asset's SHA-256 digest, recorded from GitHub's SagerNet/sing-box API.
const SING_BOX_VERSION = "1.15.0-alpha.6";
const SING_BOX_SHA256 = "e19c5e3961ae707d762dc3e6236186c33f0aaf91130567078e1b2af148cda0ae";
const ARCHIVE_NAME = `sing-box-${SING_BOX_VERSION}-linux-amd64.tar.gz`;
const ARCHIVE_URL = `https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/${ARCHIVE_NAME}`;
const SOURCE_LIMIT = 16 * 1024 * 1024;
const SRS_LIMIT = 24 * 1024 * 1024;
const RESPONSE_LIMIT = 64 * 1024;
const DEADLINE = Date.now() + 55 * 60 * 1000;
const BUCKETS = new Set(["combined", "domain", "ipcidr", "dns"]);
const FILE_DESCRIPTIONS = {
  combined: "路由匹配规则 / Routing rules", domain: "域名路由规则 / Domain routing rules",
  ipcidr: "IP 网段路由规则 / IP range routing rules", dns: "DNS 匹配域名 / DNS matching domains"
};
const DIRECTORY_README = `# SubPilot 规则集 / Rule sets

由 GitHub Actions 获取来源、合并、去重并分桶。产物分支固定为 rules。

GitHub Actions fetches sources, merges and deduplicates rules, and splits them into client-specific buckets on the fixed rules branch.

- Surge/: Surge 文本规则 / text rule sets
- Clash/: Clash YAML 规则 / YAML rule providers
- Sing-Box/: sing-box SRS 二进制规则 / binary rule sets

每个客户端目录内按规则集名称分类，仅生成所需文件。manifest.json 是发布校验信息。

Each client directory contains named rule-set folders with only the required files. manifest.json is the publication receipt.
`;
const filename = (manifest, bucket) => actionsArtifactPath(manifest.target, manifest.outputName, bucket).split("/").at(-1);

class SafeError extends Error {}

function remainingTime(limit) {
  const remaining = DEADLINE - Date.now();
  if (remaining <= 0) throw new SafeError("Compilation job exceeded its time limit.");
  return Math.min(limit, remaining);
}

async function readLimited(response, limit) {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > limit) {
    await response.body?.cancel();
    throw new SafeError("A download exceeded its size limit.");
  }
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) throw new SafeError("A download exceeded its size limit.");
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, length);
}

async function request(url, options, limit, label, attempts = 8) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    let retryDelay = Math.min(2 ** (attempt + 1), 30) * 1000;
    try {
      const response = await fetch(url, {
        ...options,
        signal: AbortSignal.timeout(remainingTime(45_000))
      });
      if (response.ok) return await readLimited(response, limit);
      const status = response.status;
      const retryAfter = Number(response.headers.get("retry-after"));
      if (Number.isFinite(retryAfter) && retryAfter > 0) {
        retryDelay = Math.max(retryDelay, Math.min(retryAfter, 30) * 1000);
      }
      let detail = "";
      if (status === 403 && new URL(url).origin === new URL(process.env.SUBPILOT_URL).origin) {
        detail = response.headers.get("cf-mitigated") === "challenge"
          ? "; Cloudflare challenged the callback request; use this deployment's workers.dev address"
          : "; callback access was refused; check the workflow callback address and its security rules";
      }
      if (label === "Publication confirmation" && status === 503) {
        try {
          const data = JSON.parse((await readLimited(response, RESPONSE_LIMIT)).toString("utf8"));
          if (["receipt_unavailable", "receipt_mismatch", "receipt_invalid", "job_changed", "job_not_visible"].includes(data.code)) detail = `; ${data.code}`;
        } catch { /* Never expose arbitrary response bodies. */ }
      } else await response.body?.cancel();
      // KV may not be visible to this runner's region immediately. A conflict
      // means the job is stale, however, and must never be published.
      if (![404, 429].includes(status) && status < 500) {
        throw new SafeError(`${label} failed (HTTP ${status}${detail}).`);
      }
      if (attempt === attempts - 1) {
        throw new SafeError(`${label} failed after retries (HTTP ${status}${detail}).`);
      }
    } catch (error) {
      if (error instanceof SafeError) throw error;
      if (attempt === attempts - 1) {
        throw new SafeError(`${label} failed after retries; check connectivity and configuration.`);
      }
    }
    process.stdout.write(`${label}: waiting before retry ${attempt + 2}/${attempts}.\n`);
    await sleep(remainingTime(retryDelay));
  }
  throw new SafeError(`${label} did not complete.`);
}

function readConfiguration() {
  const origin = process.env.SUBPILOT_URL?.trim() ?? "";
  let url;
  try {
    url = new URL(origin);
  } catch {
    throw new SafeError("Configure SUBPILOT_URL with the HTTPS origin of your SubPilot Worker.");
  }
  if (url.protocol !== "https:" || ![url.origin, `${url.origin}/`].includes(origin)) {
    throw new SafeError("SUBPILOT_URL must be an HTTPS origin without credentials, path, query or fragment.");
  }
  const secret = process.env.SUBPILOT_ACTIONS_SECRET ?? "";
  if (!/^[\x21-\x7e]{32,256}$/.test(secret)) {
    throw new SafeError("Configure SUBPILOT_ACTIONS_SECRET with 32–256 printable ASCII characters without spaces.");
  }
  const jobId = process.env.SUBPILOT_ACTIONS_JOB_ID ?? "";
  if (!/^[a-f0-9]{64}$/.test(jobId)) {
    throw new SafeError("The compilation job ID must be 64 lowercase hexadecimal characters.");
  }
  const repository = process.env.GITHUB_REPOSITORY ?? "";
  const token = process.env.GITHUB_TOKEN ?? "";
  if (!/^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(repository) || !/^[\x21-\x7e]+$/.test(token)) {
    throw new SafeError("The output key, GitHub repository or workflow token is missing or invalid.");
  }
  return { origin: url.origin, secret, jobId, repository, token };
}

function readManifest(bytes, settings) {
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new SafeError("The Worker returned an invalid compilation manifest.");
  }
  if (!manifest || manifest.protocol !== ACTIONS_COMPILER_PROTOCOL || manifest.jobId !== settings.jobId
    || !Object.hasOwn(ACTIONS_CLIENT_DIRECTORIES, manifest.target) || manifest.target !== settings.target
    || typeof manifest.repository !== "string" || manifest.repository.toLowerCase() !== settings.repository.toLowerCase()
    || typeof manifest.outputName !== "string" || manifest.outputName.length > 1024
    || actionsOutputKey(manifest.target, manifest.outputName) !== settings.outputKey
    || manifest.directory !== actionsArtifactDirectory(manifest.target, manifest.outputName)
    || manifest.manifestPath !== actionsArtifactPath(manifest.target, manifest.outputName, "manifest")
    || !/^[a-f0-9]{64}$/.test(manifest.fingerprint) || manifest.output?.name !== manifest.outputName
    || manifest.config?.renderTarget !== manifest.target || !Array.isArray(manifest.config?.ruleSets?.sources)
    || !Array.isArray(manifest.config?.ruleSets?.outputs)) {
    throw new SafeError("Invalid compilation inputs, repository or publication paths.");
  }
  return manifest;
}

function runCommand(command, args, label, captureOutput = false) {
  // The compiler and tar need no Worker credentials. Never forward their stderr:
  // parse failures can contain private domains and other rule contents.
  const result = spawnSync(command, args, {
    env: { PATH: process.env.PATH, LANG: "C", LC_ALL: "C" },
    stdio: captureOutput ? ["ignore", "pipe", "ignore"] : "ignore",
    encoding: captureOutput ? "utf8" : undefined,
    maxBuffer: RESPONSE_LIMIT,
    timeout: remainingTime(120_000),
    killSignal: "SIGKILL"
  });
  if (result.error || result.status !== 0) throw new SafeError(`${label} failed.`);
  return result.stdout;
}

async function installCompiler(directory) {
  if (process.platform !== "linux" || process.arch !== "x64") {
    throw new SafeError("This compiler script requires a Linux x64 runner.");
  }
  const archive = await request(ARCHIVE_URL, { redirect: "follow" }, 64 * 1024 * 1024, "Compiler download", 5);
  if (createHash("sha256").update(archive).digest("hex") !== SING_BOX_SHA256) {
    throw new SafeError("The sing-box release checksum did not match; installation stopped.");
  }
  const archivePath = join(directory, ARCHIVE_NAME);
  await writeFile(archivePath, archive, { mode: 0o600 });
  runCommand("tar", [
    "-xzf", archivePath,
    "--directory", directory,
    "--strip-components=1",
    `sing-box-${SING_BOX_VERSION}-linux-amd64/sing-box`
  ], "Compiler extraction");
  const compiler = join(directory, "sing-box");
  await chmod(compiler, 0o700);
  const version = runCommand(compiler, ["version"], "Compiler version check", true);
  if (version.split(/\r?\n/, 1)[0] !== `sing-box version ${SING_BOX_VERSION}`) {
    throw new SafeError("The downloaded compiler reported an unexpected version.");
  }
  await rm(archivePath);
  return compiler;
}

async function githubApi(settings, path, method = "GET", body, allowedStatuses = []) {
  const repository = settings.repository.split("/").map(encodeURIComponent).join("/");
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      const response = await fetch(`https://api.github.com/repos/${repository}${path}`, {
        method, redirect: "error", signal: AbortSignal.timeout(remainingTime(30_000)),
        headers: {
          authorization: `Bearer ${settings.token}`, accept: "application/vnd.github+json",
          "content-type": "application/json", "x-github-api-version": "2022-11-28", "user-agent": "SubPilot-Actions"
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) })
      });
      if (allowedStatuses.includes(response.status)) {
        await response.body?.cancel();
        return { status: response.status };
      }
      if (response.ok) return { status: response.status, data: JSON.parse((await readLimited(response, 256 * 1024)).toString("utf8")) };
      await response.body?.cancel();
      if (response.status !== 429 && response.status < 500) throw new SafeError(`GitHub publication failed (HTTP ${response.status}); check repository visibility, permissions and branch protection.`);
    } catch (error) {
      if (error instanceof SafeError) throw error;
    }
    if (attempt === 4) throw new SafeError("GitHub publication failed after retries.");
    await sleep(remainingTime(Math.min(2 ** (attempt + 1), 16) * 1000));
  }
}

function gitSha(result) {
  const sha = result?.data?.sha;
  if (typeof sha !== "string" || !/^[a-f0-9]{40}$/.test(sha)) throw new SafeError("GitHub returned an invalid object identifier.");
  return sha;
}

function receiptMatches(receipt, settings, manifest) {
  return receipt?.protocol === ACTIONS_COMPILER_PROTOCOL && receipt.jobId === settings.jobId && receipt.target === manifest.target
    && receipt.outputName === manifest.outputName && receipt.manifest?.outputFingerprint === manifest.fingerprint
    && Array.isArray(receipt.artifacts) && receipt.artifacts.length <= BUCKETS.size
    && new Set(receipt.artifacts.map((item) => item?.bucket)).size === receipt.artifacts.length
    && receipt.artifacts.every((item) => BUCKETS.has(item?.bucket)
      && item.path === actionsArtifactPath(manifest.target, manifest.outputName, item.bucket) && /^[a-f0-9]{64}$/.test(item.sha256));
}

function outputReadme(manifest) {
  const title = manifest.outputName.replace(/[\p{C}\s]+/gu, " ")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/[\\`*_[\]{}()#!|]/g, "\\$&");
  return `# ${title}\n\n`
    + "由 SubPilot 自动维护；只生成本规则集需要的文件。\n\nAutomatically maintained by SubPilot; only files needed by this rule set are generated.\n\n"
    + "| 文件 / File | 用途 / Purpose |\n| --- | --- |\n"
    + manifest.artifacts.map(({ bucket }) => `| [${filename(manifest, bucket)}](./${filename(manifest, bucket)}) | ${FILE_DESCRIPTIONS[bucket]} |`).join("\n")
    + "\n| [manifest.json](./manifest.json) | 发布校验信息 / Publication receipt |\n\n"
    + "[全部规则集 / All rule sets](../)\n";
}

async function publishArtifacts(settings, manifest, artifacts, workerRequest) {
  const repository = (await githubApi(settings, "")).data;
  if (repository?.private !== false || repository.default_branch === ACTIONS_OUTPUT_BRANCH
    || ACTIONS_OUTPUT_BRANCH === process.env.GITHUB_REF_NAME) {
    throw new SafeError("Use a public repository and a dedicated output branch distinct from the default and workflow branches.");
  }
  const entries = [];
  for (const { bucket, binary } of artifacts) {
    const blob = await githubApi(settings, "/git/blobs", "POST", { encoding: "base64", content: binary.toString("base64") });
    entries.push({ path: filename(manifest, bucket), mode: "100644", type: "blob", sha: gitSha(blob) });
  }
  const receipt = {
    protocol: ACTIONS_COMPILER_PROTOCOL, jobId: settings.jobId, target: manifest.target,
    outputName: manifest.outputName, manifest: manifest.compiledMetadata,
    artifacts: artifacts.map(({ bucket, binary }) => ({
      bucket, path: `${manifest.directory}/${filename(manifest, bucket)}`, sha256: createHash("sha256").update(binary).digest("hex")
    }))
  };
  const receiptEntry = { path: "manifest.json", mode: "100644", type: "blob", content: JSON.stringify(receipt, null, 2) + "\n" };
  entries.push(receiptEntry);
  entries.push({ path: "README.md", mode: "100644", type: "blob", content: outputReadme(manifest) });
  const outputTree = gitSha(await githubApi(settings, "/git/trees", "POST", { tree: entries }));
  const branch = encodeURIComponent(ACTIONS_OUTPUT_BRANCH);
  for (let attempt = 0; attempt < 6; attempt += 1) {
    // Revalidate immediately before every publication attempt. An old run cannot
    // republish after its rule plan, source revision or integration has changed.
    await workerRequest("/current", "GET", RESPONSE_LIMIT, "Publication validation");
    const head = await githubApi(settings, `/git/ref/heads/${branch}`, "GET", undefined, [404]);
    const parent = head.data?.object?.sha;
    if (head.status !== 404 && (typeof parent !== "string" || !/^[a-f0-9]{40}$/.test(parent))) throw new SafeError("GitHub returned an invalid branch head.");
    const base = parent ? (await githubApi(settings, `/git/commits/${parent}`)).data?.tree?.sha : undefined;
    if (parent && (typeof base !== "string" || !/^[a-f0-9]{40}$/.test(base))) throw new SafeError("GitHub returned an invalid branch tree.");
    // Replace this output atomically, removing obsolete buckets while keeping
    // every other rule set intact.
    const updates = [
      { path: manifest.directory, mode: "040000", type: "tree", sha: outputTree },
      { path: "README.md", mode: "100644", type: "blob", content: DIRECTORY_README }
    ];
    const tree = gitSha(await githubApi(settings, "/git/trees", "POST", {
      ...(base ? { base_tree: base } : {}),
      tree: updates
    }));
    const commit = gitSha(await githubApi(settings, "/git/commits", "POST", {
      message: `Update rule set: ${manifest.directory}`, tree, parents: parent ? [parent] : []
    }));
    const result = parent
      ? await githubApi(settings, `/git/refs/heads/${branch}`, "PATCH", { sha: commit, force: false }, [409, 422])
      : await githubApi(settings, "/git/refs", "POST", { ref: `refs/heads/${ACTIONS_OUTPUT_BRANCH}`, sha: commit }, [409, 422]);
    if (result.status === 200 || result.status === 201) return commit;
    // Other rule sets can advance the same branch; retry from its current head
    // without force-pushing or losing their files.
    await sleep(remainingTime((attempt + 1) * 1000));
  }
  throw new SafeError("Publication could not advance the output branch; check branch protection or retry.");
}

async function compileOutput(settings, directory, getCompiler, sourceCache) {
  const jobUrl = `${settings.origin}/api/internal/actions-compiler/jobs/${settings.jobId}`;
  const workerRequest = (suffix, method, limit, label, body) => request(`${jobUrl}${suffix}`, {
    method, redirect: "error", headers: { Authorization: `Bearer ${settings.secret}`, ...(body ? { "Content-Type": "application/json" } : {}) }, body
  }, limit, label);
  process.stdout.write(`Stage: reading ${settings.target} compilation inputs.\n`);
  const manifest = readManifest(await workerRequest("", "GET", 16 * 1024 * 1024, "Manifest download"), settings);
  const confirm = (commit) => workerRequest("/complete", "POST", RESPONSE_LIMIT, "Publication confirmation", JSON.stringify({ commit }));
  let previous, previousCommit;
  const head = await githubApi(settings, `/git/ref/heads/${ACTIONS_OUTPUT_BRANCH}`, "GET", undefined, [404]);
  if (head.status !== 404 && /^[a-f0-9]{40}$/.test(head.data?.object?.sha)) {
    previousCommit = head.data.object.sha;
    const path = manifest.manifestPath.split("/").map(encodeURIComponent).join("/");
    const existing = await githubApi(settings, `/contents/${path}?ref=${previousCommit}`, "GET", undefined, [404]);
    if (existing.status !== 404 && existing.data?.encoding === "base64" && typeof existing.data.content === "string") {
      try { previous = JSON.parse(Buffer.from(existing.data.content, "base64").toString("utf8")); } catch { /* Rebuild malformed metadata. */ }
    }
  }
  const sourceHashes = {};
  const sources = manifest.config.ruleSets.sources;
  const isBinary = (source) => manifest.target === "sing-box" && (source.format === "sing-box-binary" || source.format === "auto" && /\.srs$/i.test(new URL(source.url).pathname));
  process.stdout.write("Stage: downloading original rule sources.\n");
  for (const source of sources) {
    if (!source.enabled || !source.url) throw new SafeError("A required rule source is disabled or missing.");
    const url = new URL(source.url);
    if (!["https:", "http:"].includes(url.protocol)) throw new SafeError("Rule sources must use HTTP or HTTPS.");
    if (isBinary(source)) continue;
    const key = `cache:ruleSetSource:${createHash("sha256").update(source.url).digest("hex")}`;
    if (!sourceCache.has(key)) {
      // Source requests receive no GitHub or Worker credentials. Keep raw input on the temporary disk, not in Git.
      const content = await request(source.url, { redirect: "follow" }, SOURCE_LIMIT, "Rule source download", 4);
      const contentType = content.subarray(0, 1024).toString("utf8").trimStart();
      if (/^(?:<!doctype\s+html|<html|<head|<body)/i.test(contentType)) throw new SafeError("A rule source returned an HTML page instead of rules.");
      const path = join(directory, `${key.split(":").at(-1)}.source`);
      const text = content.toString("utf8");
      await writeFile(path, text, { mode: 0o600 });
      sourceCache.set(key, { path, contentHash: createHash("sha256").update(text).digest("hex") });
    }
    sourceHashes[key] = sourceCache.get(key).contentHash;
  }
  const sourceContentFingerprint = createHash("sha256").update(JSON.stringify(Object.keys(sourceHashes).sort().map((key) => [key, sourceHashes[key]]))).digest("hex");
  if (receiptMatches(previous, settings, manifest) && previous.manifest.sourceContentFingerprint === sourceContentFingerprint
    && (!previous.manifest.asnExpiresAt || previous.manifest.asnExpiresAt > Date.now())) {
    process.stdout.write("Sources and compilation inputs are unchanged; confirming existing artifacts.\n");
    await confirm(previousCommit);
    return "unchanged";
  }
  process.stdout.write("Stage: merging, deduplicating and bucketing rules.\n");
  const compiled = await compileActionRuleSet(manifest.config, manifest.output, manifest.fingerprint, async (source) => {
    const key = `cache:ruleSetSource:${createHash("sha256").update(source.url).digest("hex")}`;
    const stored = sourceCache.get(key);
    if (!stored) throw new SafeError("A required source is unavailable.");
    return { content: await readFile(stored.path, "utf8"), contentHash: stored.contentHash, usedCachedContent: false };
  }, createActionAsnResolver());
  manifest.compiledMetadata = compiled.manifest;
  manifest.artifacts = compiled.artifacts.map(({ bucket }) => ({ bucket }));
  const artifacts = [];
  for (const { bucket, content } of compiled.artifacts) {
    let binary = Buffer.from(content);
    if (manifest.target === "sing-box") {
      const compiler = await getCompiler();
      const sourcePath = join(directory, `${bucket}.json`), outputPath = join(directory, `${bucket}.srs`);
      await writeFile(sourcePath, content, { mode: 0o600 });
      runCommand(compiler, ["rule-set", "compile", "--output", outputPath, sourcePath], "SRS compilation");
      const info = await stat(outputPath);
      if (!info.isFile() || info.size < 8 || info.size > SRS_LIMIT) throw new SafeError("Invalid SRS artifact size.");
      binary = await readFile(outputPath);
      if (binary.subarray(0, 3).toString("ascii") !== "SRS" || binary[3] < 1 || binary[3] > 5) throw new SafeError("Invalid SRS output.");
      await Promise.all([rm(sourcePath), rm(outputPath)]);
    }
    if (binary.length > SRS_LIMIT) throw new SafeError("A rule artifact exceeds the publication size limit.");
    artifacts.push({ bucket, binary });
  }
  process.stdout.write("Stage: publishing client-specific artifacts.\n");
  const commit = await publishArtifacts(settings, manifest, artifacts, workerRequest);
  await confirm(commit);
  process.stdout.write("Publication confirmed.\n");
  return "completed";
}

async function main() {
  const settings = readConfiguration();
  const directory = await mkdtemp(join(tmpdir(), "subpilot-actions-"));
  let compiler;
  const getCompiler = async () => {
    if (!compiler) {
      process.stdout.write("Stage: downloading and verifying sing-box compiler.\n");
      compiler = await installCompiler(directory);
    }
    return compiler;
  };
  try {
    const sourceCache = new Map();
    let offset = 0, failed = 0, completed = 0, skipped = 0;
    do {
      const bytes = await request(`${settings.origin}/api/internal/actions-compiler/batch?batch=${settings.jobId}&offset=${offset}`, {
        method: "GET", redirect: "error", headers: { Authorization: `Bearer ${settings.secret}` }
      }, RESPONSE_LIMIT, "Batch manifest download");
      const batch = JSON.parse(bytes.toString("utf8"));
      if (!Array.isArray(batch.jobs) || batch.jobs.length > 5 || (batch.nextOffset !== null && (!Number.isSafeInteger(batch.nextOffset) || batch.nextOffset <= offset))) throw new SafeError("Invalid batch manifest.");
      for (const job of batch.jobs) {
        if (!/^[a-f0-9]{64}$/.test(job.jobId) || !/^[a-f0-9]{64}$/.test(job.outputKey) || !Object.hasOwn(ACTIONS_CLIENT_DIRECTORIES, job.target)) throw new SafeError("Invalid batch job.");
        try {
          const result = await compileOutput({ ...settings, jobId: job.jobId, outputKey: job.outputKey, target: job.target }, directory, getCompiler, sourceCache);
          if (result === "unchanged") skipped++; else completed++;
        } catch (error) {
          failed++;
          process.stderr.write(`${error instanceof SafeError ? error.message : "Rule-set processing failed."}\n`);
        }
      }
      offset = batch.nextOffset;
    } while (offset !== null);
    process.stdout.write(`Batch summary: ${completed} completed, ${skipped} already current, ${failed} failed.\n`);
    if (failed) throw new SafeError("Batch finished with failed rule sets; see errors above. Successful outputs will be skipped on retry.");
  } finally { await rm(directory, { recursive: true, force: true }); }
}

try {
  await main();
} catch (error) {
  // Do not log raw fetch, filesystem or compiler errors: they may disclose URLs,
  // credentials or rule contents even when GitHub's secret masking is enabled.
  process.stderr.write(`${error instanceof SafeError ? error.message : "Compilation failed; check Worker settings and runner availability."}\n`);
  process.exitCode = 1;
}
