import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import express, { type NextFunction, type Request, type Response } from "express";
import { Client } from "ssh2";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { createOAuthModule } from "./oauth.js";

type RemoteResult = {
  stdout: string;
  stderr: string;
  code: number | null;
  signal: string | null;
};

type SessionEntry = {
  server: McpServer;
  transport: StreamableHTTPServerTransport;
};

const PORT = intFromEnv("PORT", 8787, { min: 1, max: 65535 });
const MCP_SERVER_NAME = process.env.MCP_SERVER_NAME ?? "code-sherpa";
const MCP_SERVER_VERSION = process.env.MCP_SERVER_VERSION ?? "0.1.0";
const SSH_HOST = process.env.SSH_HOST ?? "192.0.2.17";
const SSH_PORT = intFromEnv("SSH_PORT", 22, { min: 1, max: 65535 });
const SSH_USERNAME = process.env.SSH_USERNAME ?? "readonly_user";
const SSH_PRIVATE_KEY_PATH = process.env.SSH_PRIVATE_KEY_PATH ?? "/run/secrets/id_ed25519";
const SSH_KNOWN_HOSTS_PATH = process.env.SSH_KNOWN_HOSTS_PATH ?? "/run/secrets/known_hosts";
const SSH_READY_TIMEOUT_MS = intFromEnv("SSH_READY_TIMEOUT_MS", 10000, { min: 1000, max: 120000 });
const SSH_EXEC_TIMEOUT_MS = intFromEnv("SSH_EXEC_TIMEOUT_MS", 15000, { min: 1000, max: 300000 });
const REPO_ROOT = process.env.REPO_ROOT ?? "/srv/repos/project-repo";
const MAX_FILE_BYTES = intFromEnv("MAX_FILE_BYTES", 100_000, { min: 1, max: 100_000_000 });
const MAX_WRITE_BYTES = intFromEnv("MAX_WRITE_BYTES", 100_000, { min: 1, max: 100_000_000 });
const MAX_SEARCH_RESULTS = intFromEnv("MAX_SEARCH_RESULTS", 100, { min: 1, max: 2000 });
const MAX_LOG_COMMITS = intFromEnv("MAX_LOG_COMMITS", 30, { min: 1, max: 500 });
const MAX_RESPONSE_CHARS = intFromEnv("MAX_RESPONSE_CHARS", 200_000, { min: 1_000, max: 20_000_000 });
const MCP_BEARER_TOKEN = process.env.MCP_BEARER_TOKEN?.trim();
const OAUTH_ISSUER_BASE_URL = requiredStringFromEnv("OAUTH_ISSUER_BASE_URL");
const OAUTH_LOGIN_USERNAME = requiredStringFromEnv("OAUTH_LOGIN_USERNAME");
const OAUTH_LOGIN_PASSWORD = requiredStringFromEnv("OAUTH_LOGIN_PASSWORD");
const OAUTH_SESSION_SECRET = requiredStringFromEnv("OAUTH_SESSION_SECRET");
const OAUTH_COOKIE_SECURE = boolFromEnv("OAUTH_COOKIE_SECURE", OAUTH_ISSUER_BASE_URL.startsWith("https://"));

const DENY_PATH_SEGMENTS = (process.env.DENY_PATH_SEGMENTS ?? ".git,node_modules,dist,build,.next,.turbo,.cache,.env,.env.local,.env.production,.ssh")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const DENY_SEGMENT_SET = new Set(DENY_PATH_SEGMENTS);

const SSH_PRIVATE_KEY = readRequiredFile(SSH_PRIVATE_KEY_PATH, "SSH private key");
const KNOWN_HOST_KEY_SET = parseKnownHostsKeys(readRequiredFile(SSH_KNOWN_HOSTS_PATH, "known_hosts"));

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

const oauthModule = createOAuthModule({
  issuerBaseUrl: OAUTH_ISSUER_BASE_URL,
  loginUsername: OAUTH_LOGIN_USERNAME,
  loginPassword: OAUTH_LOGIN_PASSWORD,
  sessionSecret: OAUTH_SESSION_SECRET,
  fixedBearerToken: MCP_BEARER_TOKEN,
  secureCookies: OAUTH_COOKIE_SECURE,
  logger: audit,
});
app.use(oauthModule.router);

const sessions = new Map<string, SessionEntry>();

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    server: MCP_SERVER_NAME,
    version: MCP_SERVER_VERSION,
    repoRoot: REPO_ROOT,
    ssh: {
      host: SSH_HOST,
      port: SSH_PORT,
      username: SSH_USERNAME,
      knownHostKeys: KNOWN_HOST_KEY_SET.size,
    },
    authEnabled: true,
    auth: {
      oauthIssuer: OAUTH_ISSUER_BASE_URL,
      staticBearerEnabled: Boolean(MCP_BEARER_TOKEN),
    },
    ts: new Date().toISOString(),
  });
});

app.use("/mcp", (req, res, next) => {
  const authResult = oauthModule.authenticateMcpBearer(req.header("authorization") ?? undefined);
  if (!authResult.ok) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  audit("mcp_auth_success", { source: authResult.source, subject: authResult.subject, scopes: authResult.scopes });
  res.locals.authScopes = authResult.scopes ?? [];
  next();
});

app.post("/mcp", async (req, res) => {
  audit("http_mcp_post", {
    hasSession: typeof req.headers["mcp-session-id"] === "string",
    bodyMethod: isObject(req.body) ? (req.body as Record<string, unknown>).method : undefined,
  });

  try {
    const headerSessionId = headerString(req, "mcp-session-id");
    if (headerSessionId) {
      const entry = sessions.get(headerSessionId);
      if (!entry) {
        res.status(404).json({ error: "Unknown or expired MCP session" });
        return;
      }
      await entry.transport.handleRequest(req, res, req.body);
      return;
    }

    if (!isInitializeRequest(req.body)) {
      res.status(400).json({ error: "Expected initialize request when session is not provided" });
      return;
    }

    const scopes: string[] = res.locals.authScopes ?? [];
    const server = createMcpServer({ hasWriteScope: scopes.includes("mcp:write") });
    let transport: StreamableHTTPServerTransport;
    transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (sessionId) => {
        sessions.set(sessionId, { server, transport });
        audit("mcp_session_initialized", { sessionId });
      },
    });

    let closing = false;
    transport.onclose = () => {
      if (closing) return;
      closing = true;
      const sessionId = transport.sessionId;
      if (sessionId) {
        sessions.delete(sessionId);
      }
      void server.close().catch((error) => {
        audit("mcp_session_close_error", { error: stringifyError(error), sessionId });
      });
    };

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    audit("http_mcp_post_error", { error: stringifyError(error) });
    if (!res.headersSent) {
      res.status(500).json({ error: "Internal server error" });
    }
  }
});

app.get("/mcp", async (req, res) => {
  const sessionId = headerString(req, "mcp-session-id");
  if (!sessionId) {
    res.status(400).json({ error: "Missing mcp-session-id header" });
    return;
  }

  const entry = sessions.get(sessionId);
  if (!entry) {
    res.status(404).json({ error: "Unknown or expired MCP session" });
    return;
  }

  try {
    await entry.transport.handleRequest(req, res);
  } catch (error) {
    audit("http_mcp_get_error", { error: stringifyError(error), sessionId });
    if (!res.headersSent) {
      res.status(500).json({ error: "Internal server error" });
    }
  }
});

app.delete("/mcp", async (req, res) => {
  const sessionId = headerString(req, "mcp-session-id");
  if (!sessionId) {
    res.status(400).json({ error: "Missing mcp-session-id header" });
    return;
  }

  const entry = sessions.get(sessionId);
  if (!entry) {
    res.status(404).json({ error: "Unknown or expired MCP session" });
    return;
  }

  try {
    await entry.transport.handleRequest(req, res);
    sessions.delete(sessionId);
    await entry.server.close();
  } catch (error) {
    audit("http_mcp_delete_error", { error: stringifyError(error), sessionId });
    if (!res.headersSent) {
      res.status(500).json({ error: "Internal server error" });
    }
  }
});

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  audit("unhandled_express_error", { error: stringifyError(err) });
  if (!res.headersSent) {
    res.status(500).json({ error: "Internal server error" });
  }
});

const httpServer = app.listen(PORT, "0.0.0.0", () => {
  audit("server_started", {
    port: PORT,
    mcpServerName: MCP_SERVER_NAME,
    mcpServerVersion: MCP_SERVER_VERSION,
    repoRoot: REPO_ROOT,
    sshHost: SSH_HOST,
    sshPort: SSH_PORT,
    sshUser: SSH_USERNAME,
    authEnabled: Boolean(MCP_BEARER_TOKEN),
  });
});

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

async function shutdown() {
  audit("shutdown_begin", { activeSessions: sessions.size });
  httpServer.close();
  await Promise.allSettled(
    Array.from(sessions.entries()).map(async ([sessionId, entry]) => {
      sessions.delete(sessionId);
      try {
        await entry.transport.close();
      } catch {
        // no-op
      }
      await entry.server.close();
    }),
  );
  audit("shutdown_done", {});
  process.exit(0);
}

function createMcpServer(opts: { hasWriteScope: boolean }): McpServer {
  const server = new McpServer({
    name: MCP_SERVER_NAME,
    version: MCP_SERVER_VERSION,
  });
  const gitBaseArgs = ["git", "-c", "safe.directory=*", "-C", REPO_ROOT];

  server.registerTool(
    "healthcheck_remote",
    {
      description: "Check SSH connectivity and basic repository health on remote host.",
      annotations: { readOnlyHint: true },
    },
    async () => {
      try {
        const hostname = await runRemoteScript("hostname");
        const repoExists = await runRemoteScript(`[ -d ${shQuote(REPO_ROOT)} ] && echo true || echo false`);
        const isGitRepo = await runRemoteScript(
          `${shellJoin([...gitBaseArgs, "rev-parse", "--is-inside-work-tree"])} 2>/dev/null || echo false`,
        );
        const payload = {
          ok: true,
          host: SSH_HOST,
          hostname: hostname.stdout.trim(),
          repoRoot: REPO_ROOT,
          repoExists: repoExists.stdout.trim() === "true",
          isGitRepo: isGitRepo.stdout.trim() === "true",
        };
        return okToolResult(payload);
      } catch (error) {
        return errorToolResult(error);
      }
    },
  );

  server.registerTool(
    "git_status",
    {
      description: "Get git status in the target repository.",
      annotations: { readOnlyHint: true },
    },
    async () => {
      try {
        const result = await runRemoteScript(shellJoin([...gitBaseArgs, "status", "--short", "--branch"]));
        return okToolResult({
          repoRoot: REPO_ROOT,
          stdout: clipText(result.stdout),
          stderr: clipText(result.stderr),
          exitCode: result.code,
        });
      } catch (error) {
        return errorToolResult(error);
      }
    },
  );

  server.registerTool(
    "git_diff",
    {
      description: "Get git diff from repository. Optionally specify commit range and path.",
      inputSchema: {
        range: z.string().min(1).max(200).optional(),
        path: z.string().min(1).max(2000).optional(),
        contextLines: z.number().int().min(0).max(50).optional(),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ range, path: inputPath, contextLines }) => {
      try {
        const safePath = inputPath ? normalizeRepoRelativePath(inputPath) : undefined;
        const unified = clamp(contextLines ?? 3, 0, 50);
        const args = [...gitBaseArgs, "diff", "--no-color", `--unified=${unified}`];
        if (range) {
          args.push(range);
        }
        if (safePath) {
          args.push("--", safePath);
        }

        const result = await runRemoteScript(shellJoin(args));
        return okToolResult({
          repoRoot: REPO_ROOT,
          range: range ?? null,
          path: safePath ?? null,
          stdout: clipText(result.stdout),
          stderr: clipText(result.stderr),
          exitCode: result.code,
        });
      } catch (error) {
        return errorToolResult(error);
      }
    },
  );

  server.registerTool(
    "git_log",
    {
      description: "Get recent git commit log for the repository.",
      inputSchema: {
        limit: z.number().int().min(1).max(500).optional(),
        path: z.string().min(1).max(2000).optional(),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ limit, path: inputPath }) => {
      try {
        const safePath = inputPath ? normalizeRepoRelativePath(inputPath) : undefined;
        const finalLimit = clamp(limit ?? MAX_LOG_COMMITS, 1, MAX_LOG_COMMITS);
        const args = [...gitBaseArgs, "log", "--no-color", `--max-count=${finalLimit}`, "--date=iso-strict", "--pretty=format:%h %ad %an %s"];
        if (safePath) {
          args.push("--", safePath);
        }

        const result = await runRemoteScript(shellJoin(args));
        const lines = result.stdout
          .split(/\r?\n/)
          .map((line) => line.trimEnd())
          .filter((line) => line.length > 0);
        return okToolResult({
          repoRoot: REPO_ROOT,
          count: lines.length,
          commits: lines,
          stderr: clipText(result.stderr),
          exitCode: result.code,
        });
      } catch (error) {
        return errorToolResult(error);
      }
    },
  );

  server.registerTool(
    "list_files",
    {
      description: "List files/directories under repository path with deny-path filtering.",
      inputSchema: {
        path: z.string().min(1).max(2000).optional(),
        depth: z.number().int().min(1).max(12).optional(),
        limit: z.number().int().min(1).max(2000).optional(),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ path: inputPath, depth, limit }) => {
      try {
        const safePath = normalizeRepoRelativePath(inputPath ?? ".");
        const maxDepth = clamp(depth ?? 4, 1, 12);
        const maxItems = clamp(limit ?? MAX_SEARCH_RESULTS, 1, MAX_SEARCH_RESULTS);

        const target = safePath === "." ? "." : safePath;
        const pruneExpr = DENY_PATH_SEGMENTS.map((segment) => `${shellJoin(["-name", segment])}`).join(" -o ");

        const script = [
          "set -euo pipefail",
          `cd ${shQuote(REPO_ROOT)}`,
          `target=${shQuote(target)}`,
          "if [ -f \"$target\" ]; then",
          "  printf '%s\\n' \"$target\"",
          "else",
          `  find \"$target\" -mindepth 1 -maxdepth ${maxDepth} \\( ${pruneExpr} \\) -prune -o -print | sed 's#^\\./##'`,
          "fi",
        ].join("\n");

        const result = await runRemoteScript(script);
        const allItems = result.stdout
          .split(/\r?\n/)
          .map((item) => item.trim())
          .filter((item) => item.length > 0)
          .filter((item) => !containsDeniedSegment(item));

        const limitedItems = allItems.slice(0, maxItems);
        return okToolResult({
          repoRoot: REPO_ROOT,
          path: safePath,
          depth: maxDepth,
          total: allItems.length,
          returned: limitedItems.length,
          truncated: allItems.length > limitedItems.length,
          items: limitedItems,
          stderr: clipText(result.stderr),
          exitCode: result.code,
        });
      } catch (error) {
        return errorToolResult(error);
      }
    },
  );

  server.registerTool(
    "read_file",
    {
      description: "Read a repository file (read-only, with size limit and deny-path filtering).",
      inputSchema: {
        path: z.string().min(1).max(2000),
        startLine: z.number().int().min(1).max(2_000_000).optional(),
        endLine: z.number().int().min(1).max(2_000_000).optional(),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ path: inputPath, startLine, endLine }) => {
      try {
        const safePath = normalizeRepoRelativePath(inputPath);

        const statResult = await runRemoteScript(
          [
            "set -euo pipefail",
            `cd ${shQuote(REPO_ROOT)}`,
            `target=${shQuote(safePath)}`,
            "[ -f \"$target\" ]",
            "wc -c < \"$target\"",
          ].join("\n"),
        );

        const fileBytes = Number.parseInt(statResult.stdout.trim(), 10);
        if (!Number.isFinite(fileBytes)) {
          throw new Error("Failed to detect file size");
        }
        if (fileBytes > MAX_FILE_BYTES) {
          throw new Error(`File exceeds MAX_FILE_BYTES (${fileBytes} > ${MAX_FILE_BYTES})`);
        }

        let textResult: RemoteResult;
        if (startLine || endLine) {
          const from = startLine ?? 1;
          const to = endLine ?? from + 2000;
          if (to < from) {
            throw new Error("endLine must be greater than or equal to startLine");
          }
          textResult = await runRemoteScript(
            [
              "set -euo pipefail",
              `cd ${shQuote(REPO_ROOT)}`,
              `sed -n ${shQuote(`${from},${to}p`)} ${shQuote(safePath)}`,
            ].join("\n"),
          );
        } else {
          textResult = await runRemoteScript(
            ["set -euo pipefail", `cd ${shQuote(REPO_ROOT)}`, `cat ${shQuote(safePath)}`].join("\n"),
          );
        }

        return okToolResult({
          repoRoot: REPO_ROOT,
          path: safePath,
          fileBytes,
          startLine: startLine ?? null,
          endLine: endLine ?? null,
          content: clipText(textResult.stdout),
          stderr: clipText(textResult.stderr),
          exitCode: textResult.code,
        });
      } catch (error) {
        return errorToolResult(error);
      }
    },
  );

  server.registerTool(
    "search_code",
    {
      description: "Search text in repository using recursive grep with result limit.",
      inputSchema: {
        query: z.string().min(1).max(300),
        path: z.string().min(1).max(2000).optional(),
        limit: z.number().int().min(1).max(2000).optional(),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ query, path: inputPath, limit }) => {
      try {
        const safePath = normalizeRepoRelativePath(inputPath ?? ".");
        const maxItems = clamp(limit ?? MAX_SEARCH_RESULTS, 1, MAX_SEARCH_RESULTS);

        const grepArgs = [
          "grep",
          "-RIn",
          "--binary-files=without-match",
          ...DENY_PATH_SEGMENTS.flatMap((segment) => ["--exclude-dir", segment]),
          ...DENY_PATH_SEGMENTS.flatMap((segment) => ["--exclude", segment]),
          "--",
          query,
          safePath,
        ];

        const script = [
          "set -euo pipefail",
          `cd ${shQuote(REPO_ROOT)}`,
          `${shellJoin(grepArgs)} || true`,
        ].join("\n");

        const result = await runRemoteScript(script);
        const matches = result.stdout
          .split(/\r?\n/)
          .map((line) => line.trimEnd())
          .filter((line) => line.length > 0)
          .filter((line) => {
            const firstColon = line.indexOf(":");
            const rel = firstColon >= 0 ? line.slice(0, firstColon) : line;
            return !containsDeniedSegment(rel);
          });

        const limitedMatches = matches.slice(0, maxItems);
        return okToolResult({
          repoRoot: REPO_ROOT,
          query,
          path: safePath,
          total: matches.length,
          returned: limitedMatches.length,
          truncated: matches.length > limitedMatches.length,
          matches: limitedMatches,
          stderr: clipText(result.stderr),
          exitCode: result.code,
        });
      } catch (error) {
        return errorToolResult(error);
      }
    },
  );

  server.registerTool(
    "search_files",
    {
      description:
        "Search for files in the repository by filename pattern (glob or partial name match). " +
        "Patterns without wildcard characters are treated as partial matches (e.g. 'config' matches 'webpack.config.js'). " +
        "Excludes .git, node_modules, and other denied paths.",
      inputSchema: {
        pattern: z.string().min(1).max(300),
        path: z.string().min(1).max(2000).optional(),
        maxResults: z.number().int().min(1).max(2000).optional(),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ pattern, path: inputPath, maxResults }) => {
      try {
        const safePath = normalizeRepoRelativePath(inputPath ?? ".");
        const maxItems = clamp(maxResults ?? 50, 1, MAX_SEARCH_RESULTS);

        // Wrap bare strings in wildcards for partial-match behaviour
        const namePattern = /[*?[]/.test(pattern) ? pattern : `*${pattern}*`;
        const pruneExpr = DENY_PATH_SEGMENTS.map((segment) => shellJoin(["-name", segment])).join(" -o ");

        const script = [
          "set -euo pipefail",
          `cd ${shQuote(REPO_ROOT)}`,
          `find ${shQuote(safePath)} \\( ${pruneExpr} \\) -prune -o -type f -name ${shQuote(namePattern)} -print | sed 's#^\\./##'`,
        ].join("\n");

        const result = await runRemoteScript(script);
        const allFiles = result.stdout
          .split(/\r?\n/)
          .map((f) => f.trim())
          .filter((f) => f.length > 0)
          .filter((f) => !containsDeniedSegment(f));

        const limitedFiles = allFiles.slice(0, maxItems);
        return okToolResult({
          repoRoot: REPO_ROOT,
          pattern,
          path: safePath,
          total: allFiles.length,
          returned: limitedFiles.length,
          truncated: allFiles.length > limitedFiles.length,
          files: limitedFiles,
          stderr: clipText(result.stderr),
          exitCode: result.code,
        });
      } catch (error) {
        return errorToolResult(error);
      }
    },
  );

  server.registerTool(
    "get_symbols",
    {
      description:
        "List symbols (functions, classes, types, interfaces, enums, exports) in a file with line numbers. " +
        "Optimised for TypeScript/JavaScript.",
      inputSchema: {
        path: z.string().min(1).max(2000),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ path: inputPath }) => {
      try {
        const safePath = normalizeRepoRelativePath(inputPath);

        // Match common TS/JS top-level declaration patterns
        const pattern = [
          "^[[:space:]]*(export[[:space:]]+)?(default[[:space:]]+)?(async[[:space:]]+)?function[[:space:]]+[a-zA-Z_$]",
          "^[[:space:]]*(export[[:space:]]+)?(abstract[[:space:]]+)?class[[:space:]]+[a-zA-Z_$]",
          "^[[:space:]]*(export[[:space:]]+)?const[[:space:]]+[a-zA-Z_$]",
          "^[[:space:]]*(export[[:space:]]+)?type[[:space:]]+[a-zA-Z_$]",
          "^[[:space:]]*(export[[:space:]]+)?interface[[:space:]]+[a-zA-Z_$]",
          "^[[:space:]]*(export[[:space:]]+)?enum[[:space:]]+[a-zA-Z_$]",
        ].join("|");

        const script = [
          "set -euo pipefail",
          `cd ${shQuote(REPO_ROOT)}`,
          `[ -f ${shQuote(safePath)} ] || { echo "File not found: ${safePath}" >&2; exit 1; }`,
          `grep -nE ${shQuote(pattern)} ${shQuote(safePath)} || true`,
        ].join("\n");

        const result = await runRemoteScript(script);
        const symbols = result.stdout
          .split(/\r?\n/)
          .map((line) => line.trimEnd())
          .filter((line) => line.length > 0);

        return okToolResult({
          repoRoot: REPO_ROOT,
          path: safePath,
          total: symbols.length,
          symbols,
          stderr: clipText(result.stderr),
          exitCode: result.code,
        });
      } catch (error) {
        return errorToolResult(error);
      }
    },
  );

  server.registerTool(
    "git_blame",
    {
      description:
        "Show per-line commit information for a repository file using git blame. " +
        "Returns porcelain-format output for structured parsing.",
      inputSchema: {
        path: z.string().min(1).max(2000),
        startLine: z.number().int().min(1).max(2_000_000).optional(),
        endLine: z.number().int().min(1).max(2_000_000).optional(),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ path: inputPath, startLine, endLine }) => {
      try {
        const safePath = normalizeRepoRelativePath(inputPath);

        if (startLine !== undefined && endLine !== undefined && endLine < startLine) {
          throw new Error("endLine must be greater than or equal to startLine");
        }

        const rangeFlag =
          startLine !== undefined || endLine !== undefined
            ? `-L ${shQuote(`${startLine ?? 1},${endLine ?? (startLine ?? 1) + 2000}`)}`
            : "";

        const script = [
          "set -euo pipefail",
          `cd ${shQuote(REPO_ROOT)}`,
          `[ -f ${shQuote(safePath)} ] || { echo "File not found: ${safePath}" >&2; exit 1; }`,
          `git blame ${rangeFlag} --porcelain -- ${shQuote(safePath)}`,
        ].join("\n");

        const result = await runRemoteScript(script);
        return okToolResult({
          repoRoot: REPO_ROOT,
          path: safePath,
          startLine: startLine ?? null,
          endLine: endLine ?? null,
          blame: clipText(result.stdout),
          stderr: clipText(result.stderr),
          exitCode: result.code,
        });
      } catch (error) {
        return errorToolResult(error);
      }
    },
  );

  if (opts.hasWriteScope) {

  server.registerTool(
    "write_file",
    {
      description:
        "Create or overwrite a file in the repository. Content is written atomically via a temp file. " +
        "Subject to deny-path filtering and size limits.",
      inputSchema: {
        path: z.string().min(1).max(2000),
        content: z.string().max(MAX_WRITE_BYTES),
      },
      annotations: { readOnlyHint: false },
    },
    async ({ path: inputPath, content }) => {
      try {
        const safePath = normalizeRepoRelativePath(inputPath);
        const contentBytes = Buffer.byteLength(content, "utf8");
        if (contentBytes > MAX_WRITE_BYTES) {
          throw new Error(`Content exceeds MAX_WRITE_BYTES (${contentBytes} > ${MAX_WRITE_BYTES})`);
        }

        const script = [
          "set -euo pipefail",
          `cd ${shQuote(REPO_ROOT)}`,
          `mkdir -p $(dirname ${shQuote(safePath)})`,
          `tmp=$(mktemp ${shQuote(safePath + ".XXXXXX")})`,
          `cat > "$tmp"`,
          `mv -f "$tmp" ${shQuote(safePath)}`,
          `wc -c < ${shQuote(safePath)}`,
        ].join("\n");

        const result = await withRetry("write_file", () => runRemoteScriptWithStdin(script, content));
        const writtenBytes = Number.parseInt(result.stdout.trim(), 10);

        audit("write_file", { path: safePath, contentBytes, writtenBytes });
        return okToolResult({
          repoRoot: REPO_ROOT,
          path: safePath,
          writtenBytes: Number.isFinite(writtenBytes) ? writtenBytes : contentBytes,
          stderr: clipText(result.stderr),
          exitCode: result.code,
        });
      } catch (error) {
        return errorToolResult(error);
      }
    },
  );

  server.registerTool(
    "delete_file",
    {
      description: "Delete a file from the repository. Subject to deny-path filtering.",
      inputSchema: {
        path: z.string().min(1).max(2000),
      },
      annotations: { readOnlyHint: false },
    },
    async ({ path: inputPath }) => {
      try {
        const safePath = normalizeRepoRelativePath(inputPath);

        const script = [
          "set -euo pipefail",
          `cd ${shQuote(REPO_ROOT)}`,
          `[ -f ${shQuote(safePath)} ] || { echo "File not found: ${safePath}" >&2; exit 1; }`,
          `rm -f ${shQuote(safePath)}`,
          `echo "deleted"`,
        ].join("\n");

        const result = await withRetry("delete_file", () => runRemoteScript(script));

        audit("delete_file", { path: safePath });
        return okToolResult({
          repoRoot: REPO_ROOT,
          path: safePath,
          deleted: true,
          stderr: clipText(result.stderr),
          exitCode: result.code,
        });
      } catch (error) {
        return errorToolResult(error);
      }
    },
  );

  server.registerTool(
    "patch_file",
    {
      description:
        "Replace a specific string in a repository file. " +
        "oldContent must match exactly once; the replacement is written atomically via a temp file. " +
        "Subject to deny-path filtering and size limits.",
      inputSchema: {
        path: z.string().min(1).max(2000),
        oldContent: z.string().min(1).max(MAX_WRITE_BYTES),
        newContent: z.string().max(MAX_WRITE_BYTES),
      },
      annotations: { readOnlyHint: false },
    },
    async ({ path: inputPath, oldContent, newContent }) => {
      try {
        const safePath = normalizeRepoRelativePath(inputPath);

        // Step 1: read the file and verify size
        const readScript = [
          "set -euo pipefail",
          `cd ${shQuote(REPO_ROOT)}`,
          `[ -f ${shQuote(safePath)} ] || { echo "File not found: ${safePath}" >&2; exit 1; }`,
          `fileSize=$(wc -c < ${shQuote(safePath)})`,
          `if [ "$fileSize" -gt ${MAX_WRITE_BYTES} ]; then`,
          `  echo "File exceeds MAX_WRITE_BYTES ($fileSize > ${MAX_WRITE_BYTES})" >&2; exit 1`,
          `fi`,
          `cat ${shQuote(safePath)}`,
        ].join("\n");

        const readResult = await withRetry("patch_file:read", () => runRemoteScript(readScript));
        const originalContent = readResult.stdout;

        const occurrences = originalContent.split(oldContent).length - 1;
        if (occurrences === 0) {
          throw new Error("oldContent not found in file");
        }
        if (occurrences > 1) {
          throw new Error(`oldContent matches ${occurrences} locations; must be unique`);
        }

        const patchedContent = originalContent.replace(oldContent, newContent);

        // Step 2: write back atomically
        const writeScript = [
          "set -euo pipefail",
          `cd ${shQuote(REPO_ROOT)}`,
          `tmp=$(mktemp ${shQuote(safePath + ".XXXXXX")})`,
          `cat > "$tmp"`,
          `mv -f "$tmp" ${shQuote(safePath)}`,
          `wc -c < ${shQuote(safePath)}`,
        ].join("\n");

        const writeResult = await withRetry("patch_file:write", () =>
          runRemoteScriptWithStdin(writeScript, patchedContent),
        );
        const writtenBytes = Number.parseInt(writeResult.stdout.trim(), 10);

        audit("patch_file", { path: safePath, writtenBytes });
        return okToolResult({
          repoRoot: REPO_ROOT,
          path: safePath,
          writtenBytes: Number.isFinite(writtenBytes) ? writtenBytes : Buffer.byteLength(patchedContent, "utf8"),
          stderr: clipText(writeResult.stderr),
          exitCode: writeResult.code,
        });
      } catch (error) {
        return errorToolResult(error);
      }
    },
  );

  } // end if (opts.hasWriteScope)

  return server;
}

async function runRemoteScriptWithStdin(script: string, stdin: string): Promise<RemoteResult> {
  audit("ssh_exec_begin", { scriptPreview: clipText(script, 200), hasStdin: true });
  return new Promise<RemoteResult>((resolve, reject) => {
    const conn = new Client();
    let stdout = "";
    let stderr = "";
    let finished = false;

    const timeout = setTimeout(() => {
      if (finished) {
        return;
      }
      finished = true;
      conn.end();
      reject(new Error(`SSH command timeout after ${SSH_EXEC_TIMEOUT_MS}ms`));
    }, SSH_EXEC_TIMEOUT_MS);

    const settle = (fn: () => void) => {
      if (finished) {
        return;
      }
      finished = true;
      clearTimeout(timeout);
      conn.end();
      fn();
    };

    conn.on("ready", () => {
      const command = `bash -lc ${shQuote(script)}`;
      conn.exec(command, (err, stream) => {
        if (err) {
          settle(() => reject(err));
          return;
        }

        stream.on("data", (chunk: Buffer | string) => {
          stdout += chunk.toString();
        });

        stream.stderr.on("data", (chunk: Buffer | string) => {
          stderr += chunk.toString();
        });

        stream.on("close", (code: number | null, signal: string | null) => {
          settle(() => {
            if (code !== 0) {
              reject(new Error(`Remote command failed (code=${code}, signal=${signal ?? "none"}): ${clipText(stderr)}`));
              return;
            }
            const output: RemoteResult = { stdout, stderr, code, signal };
            audit("ssh_exec_done", {
              code,
              signal,
              stdoutBytes: Buffer.byteLength(stdout, "utf8"),
              stderrBytes: Buffer.byteLength(stderr, "utf8"),
            });
            resolve(output);
          });
        });

        stream.end(stdin);
      });
    });

    conn.on("error", (err) => {
      settle(() => reject(err));
    });

    conn.connect({
      host: SSH_HOST,
      port: SSH_PORT,
      username: SSH_USERNAME,
      privateKey: SSH_PRIVATE_KEY,
      readyTimeout: SSH_READY_TIMEOUT_MS,
      hostVerifier: verifyHostKey,
    });
  });
}

async function runRemoteScript(script: string): Promise<RemoteResult> {
  audit("ssh_exec_begin", { scriptPreview: clipText(script, 200) });
  return new Promise<RemoteResult>((resolve, reject) => {
    const conn = new Client();
    let stdout = "";
    let stderr = "";
    let finished = false;

    const timeout = setTimeout(() => {
      if (finished) {
        return;
      }
      finished = true;
      conn.end();
      reject(new Error(`SSH command timeout after ${SSH_EXEC_TIMEOUT_MS}ms`));
    }, SSH_EXEC_TIMEOUT_MS);

    const settle = (fn: () => void) => {
      if (finished) {
        return;
      }
      finished = true;
      clearTimeout(timeout);
      conn.end();
      fn();
    };

    conn.on("ready", () => {
      const command = `bash -lc ${shQuote(script)}`;
      conn.exec(command, (err, stream) => {
        if (err) {
          settle(() => reject(err));
          return;
        }

        stream.on("data", (chunk: Buffer | string) => {
          stdout += chunk.toString();
        });

        stream.stderr.on("data", (chunk: Buffer | string) => {
          stderr += chunk.toString();
        });

        stream.on("close", (code: number | null, signal: string | null) => {
          settle(() => {
            if (code !== 0) {
              reject(new Error(`Remote command failed (code=${code}, signal=${signal ?? "none"}): ${clipText(stderr)}`));
              return;
            }
            const output: RemoteResult = { stdout, stderr, code, signal };
            audit("ssh_exec_done", {
              code,
              signal,
              stdoutBytes: Buffer.byteLength(stdout, "utf8"),
              stderrBytes: Buffer.byteLength(stderr, "utf8"),
            });
            resolve(output);
          });
        });
      });
    });

    conn.on("error", (err) => {
      settle(() => reject(err));
    });

    conn.connect({
      host: SSH_HOST,
      port: SSH_PORT,
      username: SSH_USERNAME,
      privateKey: SSH_PRIVATE_KEY,
      readyTimeout: SSH_READY_TIMEOUT_MS,
      hostVerifier: verifyHostKey,
    });
  });
}

function verifyHostKey(serverKey: Buffer | string): boolean {
  const keyB64 = toKeyBase64(serverKey);
  const accepted = Boolean(keyB64 && KNOWN_HOST_KEY_SET.has(keyB64));
  if (!accepted) {
    audit("ssh_host_verification_failed", {
      sshHost: SSH_HOST,
      keyPreview: keyB64 ? `${keyB64.slice(0, 16)}...` : "unparseable",
    });
  }
  return accepted;
}

function toKeyBase64(serverKey: Buffer | string): string | null {
  if (Buffer.isBuffer(serverKey)) {
    return serverKey.toString("base64");
  }

  const trimmed = serverKey.trim();
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
    return Buffer.from(trimmed, "hex").toString("base64");
  }
  if (/^[A-Za-z0-9+/=]+$/.test(trimmed)) {
    return trimmed;
  }
  return null;
}

function parseKnownHostsKeys(contents: string): Set<string> {
  const keySet = new Set<string>();

  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const parts = line.split(/\s+/);
    const offset = parts[0]?.startsWith("@") ? 1 : 0;
    if (parts.length < offset + 3) {
      continue;
    }

    const key = parts[offset + 2];
    if (/^[A-Za-z0-9+/=]+$/.test(key)) {
      keySet.add(key);
    }
  }

  if (keySet.size === 0) {
    throw new Error(`No host keys could be parsed from ${SSH_KNOWN_HOSTS_PATH}`);
  }

  return keySet;
}

function normalizeRepoRelativePath(inputPath: string): string {
  const raw = inputPath.trim();
  if (!raw) {
    throw new Error("Path must not be empty");
  }
  if (raw.includes("\0")) {
    throw new Error("Path contains NUL byte");
  }

  const unixPath = raw.replace(/\\/g, "/");
  if (unixPath.startsWith("/")) {
    throw new Error("Absolute paths are not allowed; use repo-relative path");
  }

  const normalized = path.posix.normalize(unixPath);
  if (normalized === ".." || normalized.startsWith("../")) {
    throw new Error("Path traversal is not allowed");
  }

  const cleaned = normalized === "." ? "." : normalized.replace(/^\.\//, "");
  if (cleaned === "") {
    return ".";
  }
  if (cleaned === ".") {
    return ".";
  }

  const segments = cleaned.split("/").filter(Boolean);
  for (const segment of segments) {
    if (segment === "." || segment === "..") {
      throw new Error("Path traversal is not allowed");
    }
    if (DENY_SEGMENT_SET.has(segment)) {
      throw new Error(`Access denied for path segment: ${segment}`);
    }
  }

  return segments.length ? segments.join("/") : ".";
}

function containsDeniedSegment(relPath: string): boolean {
  const normalized = relPath.replace(/\\/g, "/");
  return normalized
    .split("/")
    .filter(Boolean)
    .some((segment) => DENY_SEGMENT_SET.has(segment));
}

function okToolResult(payload: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: clipText(JSON.stringify(payload, null, 2)),
      },
    ],
  };
}

function errorToolResult(error: unknown) {
  const message = stringifyError(error);
  audit("tool_error", { message });
  return {
    isError: true,
    content: [
      {
        type: "text" as const,
        text: `Error: ${message}`,
      },
    ],
  };
}

const RETRY_DELAYS_MS = [500, 1000, 2000] as const;

function isRetryableError(error: unknown): boolean {
  const msg = stringifyError(error).toLowerCase();
  if (msg.includes("timeout")) return true;
  const code = (error as NodeJS.ErrnoException)?.code ?? "";
  return (["ETIMEDOUT", "ECONNRESET", "ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH", "ENOTCONN", "EPIPE"] as string[]).includes(code);
}

async function withRetry<T>(label: string, fn: () => Promise<T>): Promise<T> {
  for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt++) {
    try {
      return await fn();
    } catch (error) {
      const delayMs = RETRY_DELAYS_MS[attempt];
      if (delayMs === undefined || !isRetryableError(error)) {
        throw error;
      }
      audit("retry_attempt", { label, attempt: attempt + 1, delayMs, error: stringifyError(error) });
      await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
    }
  }
  // unreachable, but satisfies the type checker
  throw new Error("withRetry: exhausted retries");
}

function readRequiredFile(filePath: string, label: string): string {
  try {
    return readFileSync(filePath, "utf8");
  } catch (error) {
    throw new Error(`Failed to read ${label} at ${filePath}: ${stringifyError(error)}`);
  }
}

function shQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function shellJoin(args: string[]): string {
  return args.map((arg) => shQuote(arg)).join(" ");
}

function intFromEnv(name: string, fallback: number, bounds: { min: number; max: number }): number {
  const raw = process.env[name];
  if (raw == null || raw.trim() === "") {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < bounds.min || parsed > bounds.max) {
    throw new Error(`${name} must be an integer in range [${bounds.min}, ${bounds.max}]`);
  }
  return parsed;
}

function requiredStringFromEnv(name: string): string {
  const raw = process.env[name];
  if (raw == null || raw.trim() === "") {
    throw new Error(`${name} is required`);
  }
  return raw.trim();
}

function boolFromEnv(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw == null || raw.trim() === "") {
    return fallback;
  }
  const normalized = raw.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  throw new Error(`${name} must be boolean-like (true/false)`);
}

function headerString(req: Request, headerName: string): string | null {
  const value = req.headers[headerName.toLowerCase()];
  if (typeof value === "string" && value.trim() !== "") {
    return value;
  }
  if (Array.isArray(value) && value.length > 0 && value[0].trim() !== "") {
    return value[0];
  }
  return null;
}

function audit(event: string, data: Record<string, unknown>): void {
  const line = {
    ts: new Date().toISOString(),
    event,
    ...data,
  };
  console.log(JSON.stringify(line));
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function clipText(text: string, maxChars = MAX_RESPONSE_CHARS): string {
  if (text.length <= maxChars) {
    return text;
  }
  const extra = text.length - maxChars;
  return `${text.slice(0, maxChars)}\n...[truncated ${extra} chars]`;
}

function stringifyError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
