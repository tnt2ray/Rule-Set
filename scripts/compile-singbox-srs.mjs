#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

// Keep this version aligned with src/vendor/singbox. The checksum is the official
// release asset's SHA-256 digest, recorded from GitHub's SagerNet/sing-box API.
const SING_BOX_VERSION = "1.15.0-alpha.6";
const SING_BOX_SHA256 = "e19c5e3961ae707d762dc3e6236186c33f0aaf91130567078e1b2af148cda0ae";
const ARCHIVE_NAME = `sing-box-${SING_BOX_VERSION}-linux-amd64.tar.gz`;
const ARCHIVE_URL = `https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/${ARCHIVE_NAME}`;
const SOURCE_LIMIT = 16 * 1024 * 1024;
const SRS_LIMIT = 24 * 1024 * 1024;
const RESPONSE_LIMIT = 64 * 1024;
const DEADLINE = Date.now() + 11 * 60 * 1000;
const BUCKETS = new Set(["combined", "domain", "ipcidr", "dns"]);

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
      await response.body?.cancel();
      // KV may not be visible to this runner's region immediately. A conflict
      // means the job is stale, however, and must never be published.
      if (![404, 429].includes(status) && status < 500) {
        throw new SafeError(`${label} failed (HTTP ${status}).`);
      }
      if (attempt === attempts - 1) {
        throw new SafeError(`${label} failed after retries (HTTP ${status}).`);
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
  const secret = process.env.SUBPILOT_SRS_SECRET ?? "";
  if (!/^[\x21-\x7e]{32,256}$/.test(secret)) {
    throw new SafeError("Configure SUBPILOT_SRS_SECRET with 32–256 printable ASCII characters without spaces.");
  }
  const jobId = process.env.SUBPILOT_SRS_JOB_ID ?? "";
  if (!/^[a-f0-9]{64}$/.test(jobId)) {
    throw new SafeError("The compilation job ID must be 64 lowercase hexadecimal characters.");
  }
  const outputKey = process.env.SUBPILOT_SRS_OUTPUT_KEY ?? "";
  const repository = process.env.GITHUB_REPOSITORY ?? "";
  const token = process.env.GITHUB_TOKEN ?? "";
  if (!/^[a-f0-9]{64}$/.test(outputKey) || !/^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(repository) || !/^[\x21-\x7e]+$/.test(token)) {
    throw new SafeError("The output key, GitHub repository or workflow token is missing or invalid.");
  }
  return { origin: url.origin, secret, jobId, outputKey, repository, token };
}

function readManifest(bytes, settings) {
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new SafeError("The Worker returned an invalid compilation manifest.");
  }
  const artifacts = manifest?.artifacts;
  if (!Array.isArray(artifacts) || artifacts.length < 1 || artifacts.length > BUCKETS.size) {
    throw new SafeError("The compilation manifest must contain one to four rule sets.");
  }
  const buckets = artifacts.map((artifact) => artifact?.bucket);
  if (buckets.some((bucket) => !BUCKETS.has(bucket)) || new Set(buckets).size !== buckets.length) {
    throw new SafeError("The compilation manifest contains invalid or duplicate rule set names.");
  }
  if (typeof manifest.repository !== "string" || manifest.repository.toLowerCase() !== settings.repository.toLowerCase()
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(manifest.outputBranch ?? "")
    || manifest.outputBranch.includes("..") || manifest.outputBranch.endsWith(".") || manifest.outputBranch.endsWith(".lock")
    || manifest.manifestPath !== `rules/${settings.outputKey}/manifest.json`
    || artifacts.some(({ bucket, path }) => path !== `rules/${settings.outputKey}/${bucket}.srs`)) {
    throw new SafeError("The publication repository, branch or file paths are invalid.");
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
          "content-type": "application/json", "x-github-api-version": "2022-11-28", "user-agent": "SubPilot-SRS"
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

async function publishArtifacts(settings, manifest, artifacts, workerRequest) {
  const repository = (await githubApi(settings, "")).data;
  if (repository?.private !== false || repository.default_branch === manifest.outputBranch
    || manifest.outputBranch === process.env.GITHUB_REF_NAME) {
    throw new SafeError("Use a public repository and a dedicated output branch distinct from the default and workflow branches.");
  }
  const entries = [];
  for (const { bucket, binary } of artifacts) {
    const blob = await githubApi(settings, "/git/blobs", "POST", { encoding: "base64", content: binary.toString("base64") });
    entries.push({ path: `${bucket}.srs`, mode: "100644", type: "blob", sha: gitSha(blob) });
  }
  const receipt = {
    jobId: settings.jobId,
    artifacts: artifacts.map(({ bucket, binary }) => ({
      bucket, path: `rules/${settings.outputKey}/${bucket}.srs`, sha256: createHash("sha256").update(binary).digest("hex")
    }))
  };
  entries.push({ path: "manifest.json", mode: "100644", type: "blob", content: JSON.stringify(receipt) + "\n" });
  const outputTree = gitSha(await githubApi(settings, "/git/trees", "POST", { tree: entries }));
  const branch = encodeURIComponent(manifest.outputBranch);
  for (let attempt = 0; attempt < 6; attempt += 1) {
    // Revalidate immediately before every publication attempt. An old run cannot
    // republish after its rule plan, source revision or integration has changed.
    await workerRequest("", "GET", RESPONSE_LIMIT, "Publication validation");
    const head = await githubApi(settings, `/git/ref/heads/${branch}`, "GET", undefined, [404]);
    const parent = head.data?.object?.sha;
    if (head.status !== 404 && (typeof parent !== "string" || !/^[a-f0-9]{40}$/.test(parent))) throw new SafeError("GitHub returned an invalid branch head.");
    const base = parent ? (await githubApi(settings, `/git/commits/${parent}`)).data?.tree?.sha : undefined;
    if (parent && (typeof base !== "string" || !/^[a-f0-9]{40}$/.test(base))) throw new SafeError("GitHub returned an invalid branch tree.");
    // Replace only this output's subtree, preserving every other rule set and
    // removing obsolete buckets from this output in the same atomic commit.
    const tree = gitSha(await githubApi(settings, "/git/trees", "POST", {
      ...(base ? { base_tree: base } : {}),
      tree: [{ path: `rules/${settings.outputKey}`, mode: "040000", type: "tree", sha: outputTree }]
    }));
    const commit = gitSha(await githubApi(settings, "/git/commits", "POST", {
      message: "Update compiled sing-box rule set", tree, parents: parent ? [parent] : []
    }));
    const result = parent
      ? await githubApi(settings, `/git/refs/heads/${branch}`, "PATCH", { sha: commit, force: false }, [409, 422])
      : await githubApi(settings, "/git/refs", "POST", { ref: `refs/heads/${manifest.outputBranch}`, sha: commit }, [409, 422]);
    if (result.status === 200 || result.status === 201) return commit;
    // Other rule sets can advance the same branch; retry from its current head
    // without force-pushing or losing their files.
    await sleep(remainingTime((attempt + 1) * 1000));
  }
  throw new SafeError("Publication could not advance the output branch; check branch protection or retry.");
}

async function main() {
  const settings = readConfiguration();
  const jobUrl = `${settings.origin}/api/internal/singbox-srs/jobs/${settings.jobId}`;
  const workerRequest = (suffix, method, limit, label, body) => request(`${jobUrl}${suffix}`, {
    method, redirect: "error",
    headers: {
      Authorization: `Bearer ${settings.secret}`,
      ...(body ? { "Content-Type": "application/json" } : {})
    },
    body
  }, limit, label);
  const manifest = readManifest(await workerRequest("", "GET", RESPONSE_LIMIT, "Manifest download"), settings);
  const directory = await mkdtemp(join(tmpdir(), "subpilot-srs-"));
  try {
    const compiler = await installCompiler(directory);
    const artifacts = [];
    for (const { bucket } of manifest.artifacts) {
      const source = await workerRequest(`/${bucket}.json`, "GET", SOURCE_LIMIT, "Rule source download");
      const sourcePath = join(directory, `${bucket}.json`);
      const outputPath = join(directory, `${bucket}.srs`);
      await writeFile(sourcePath, source, { mode: 0o600 });
      runCommand(compiler, ["rule-set", "compile", "--output", outputPath, sourcePath], "Rule set compilation");
      const outputInfo = await stat(outputPath);
      if (!outputInfo.isFile() || outputInfo.size < 8 || outputInfo.size > SRS_LIMIT) {
        throw new SafeError("The compiled rule set is empty or exceeds the publication size limit.");
      }
      const binary = await readFile(outputPath);
      if (binary.subarray(0, 3).toString("ascii") !== "SRS" || binary[3] < 1 || binary[3] > 5) {
        throw new SafeError("The compiler did not produce a valid SRS file.");
      }
      artifacts.push({ bucket, binary });
      await Promise.all([rm(sourcePath), rm(outputPath)]);
      process.stdout.write(`Compiled ${bucket}.\n`);
    }
    const commit = await publishArtifacts(settings, manifest, artifacts, workerRequest);
    await workerRequest("/complete", "POST", RESPONSE_LIMIT, "Publication confirmation", JSON.stringify({ commit }));
    process.stdout.write("All compiled rule sets have been published to the repository.\n");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

try {
  await main();
} catch (error) {
  // Do not log raw fetch, filesystem or compiler errors: they may disclose URLs,
  // credentials or rule contents even when GitHub's secret masking is enabled.
  process.stderr.write(`${error instanceof SafeError ? error.message : "Compilation failed; check Worker settings and runner availability."}\n`);
  process.exitCode = 1;
}
