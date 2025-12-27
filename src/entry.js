/**
 * JS Wrapper Entry Point for Warden Worker
 *
 * This wrapper intercepts attachment upload and download requests for zero-copy streaming
 * to/from R2. Workers R2 binding can accept request.body directly for uploads,
 * and r2Object.body can be passed directly to Response for downloads.
 * See: https://blog.cloudflare.com/zh-cn/r2-ga/
 *
 * This avoids CPU time consumption that would occur if the body went through
 * the Rust/WASM layer with axum body conversion.
 *
 * Additionally, this wrapper can optionally offload CPU-heavy endpoints to a Rust Durable Object
 * (higher CPU budget) by binding `HEAVY_DO` in `wrangler.toml`.
 * This is used for operations like imports and password verification paths, keeping the main
 * Worker on a low-CPU fast path for typical requests.
 *
 * All other requests are passed through to the Rust WASM module.
 */

import RustWorker from "../build/index.js";
import { base64UrlDecode, handleAzureUpload, handleDownload } from "./attachments.js";

function getBearerToken(request) {
  const auth = request.headers.get("Authorization") || request.headers.get("authorization");
  if (!auth) return null;
  const m = auth.match(/^\s*Bearer\s+(.+?)\s*$/i);
  return m ? m[1] : null;
}

// Decode JWT payload WITHOUT verifying signature (used only for sharding DO instances).
// The Durable Object handler will perform full verification and reject invalid tokens.
function decodeJwtPayloadUnsafe(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const payloadB64 = parts[1];
    const payloadJson = new TextDecoder().decode(base64UrlDecode(payloadB64));
    return JSON.parse(payloadJson);
  } catch {
    return null;
  }
}

const AUTH_DO_EXACT_PATHS = new Set([
  // Login
  "/identity/connect/token",
  // Registration (server-side password hashing)
  "/identity/accounts/register",
  "/identity/accounts/register/finish",
  // Password/KDF changes
  "/api/accounts/password",
  "/api/accounts/kdf",
  // Dangerous ops requiring password verification
  "/api/accounts/delete",
  "/api/accounts",
  "/api/ciphers/purge",
  // Key rotation may verify master password
  "/api/accounts/key-management/rotate-user-account-keys",
]);

function isAuthDoPath(pathname) {
  if (AUTH_DO_EXACT_PATHS.has(pathname)) return true;
  if (pathname.startsWith("/api/two-factor")) return true;
  return false;
}

// Parse azure-upload route: /api/ciphers/{id}/attachment/{attachment_id}/azure-upload
function parseAzureUploadPath(path) {
  const parts = path.replace(/^\//, "").split("/");
  // Expected: ["api", "ciphers", "{cipher_id}", "attachment", "{attachment_id}", "azure-upload"]
  if (
    parts.length === 6 &&
    parts[0] === "api" &&
    parts[1] === "ciphers" &&
    parts[3] === "attachment" &&
    parts[5] === "azure-upload"
  ) {
    return { cipherId: parts[2], attachmentId: parts[4] };
  }
  return null;
}

// Parse download route: /api/ciphers/{id}/attachment/{attachment_id}/download
function parseDownloadPath(path) {
  const parts = path.replace(/^\//, "").split("/");
  // Expected: ["api", "ciphers", "{cipher_id}", "attachment", "{attachment_id}", "download"]
  if (
    parts.length === 6 &&
    parts[0] === "api" &&
    parts[1] === "ciphers" &&
    parts[3] === "attachment" &&
    parts[5] === "download"
  ) {
    return { cipherId: parts[2], attachmentId: parts[4] };
  }
  return null;
}

// Main fetch handler
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Optional: route selected CPU-heavy endpoints to Durable Objects.
    // This keeps the main Worker on a low-CPU path while allowing heavy work to complete.
    if (env.HEAVY_DO) {
      // Import: route to Rust Durable Object (HeavyDo) to reuse the existing Rust import logic.
      if (request.method === "POST" && url.pathname === "/api/ciphers/import") {
        // Shard by user id (JWT sub) WITHOUT verifying signature here (cheap).
        const token = getBearerToken(request);
        const sub = token ? decodeJwtPayloadUnsafe(token)?.sub : null;
        const name = sub ? `import:${sub}` : "import:default";
        const id = env.HEAVY_DO.idFromName(name);
        const stub = env.HEAVY_DO.get(id);
        return stub.fetch(request);
      }

      // Auth/password verification: run inside Rust DO (higher CPU budget).
      if (isAuthDoPath(url.pathname)) {
        let name = "auth:default";

        if (url.pathname === "/identity/connect/token") {
          // Shard login DO by username (email) to avoid serializing all logins onto one DO instance.
          try {
            const bodyText = await request.clone().text();
            const params = new URLSearchParams(bodyText);
            const username = (params.get("username") || "default").toLowerCase();
            name = `auth:login:${username}`;
          } catch {
            // Fall back to default shard.
          }
        } else {
          // Other auth endpoints are JWT-authenticated; shard by sub.
          const token = getBearerToken(request);
          const sub = token ? decodeJwtPayloadUnsafe(token)?.sub : null;
          if (sub) name = `auth:user:${sub}`;
        }

        const id = env.HEAVY_DO.idFromName(name);
        const stub = env.HEAVY_DO.get(id);
        return stub.fetch(request);
      }
    }

    // Attachment upload/download fast-path (R2 zero-copy streaming + JWT validation)
    if (request.method === "PUT") {
      const parsed = parseAzureUploadPath(url.pathname);
      if (parsed) {
        const token = url.searchParams.get("token");
        if (!token) {
          return new Response(
            JSON.stringify({ error: "Missing upload token" }), 
            { status: 401, headers: { "Content-Type": "application/json" } }
          );
        }
        return handleAzureUpload(
            request,
            env,
            parsed.cipherId,
            parsed.attachmentId,
            token
          );
      }
    }

    if (request.method === "GET") {
      const parsed = parseDownloadPath(url.pathname);
      if (parsed) {
        const token = url.searchParams.get("token");
        if (!token) {
          return new Response(
            JSON.stringify({ error: "Missing download token" }),
            { status: 401, headers: { "Content-Type": "application/json" } }
          );
        }
        return handleDownload(
          request,
          env,
          parsed.cipherId,
          parsed.attachmentId,
          token
        );
      }
    }

    // Pass all other requests to Rust WASM
    const worker = new RustWorker(ctx, env);
    return worker.fetch(request);
  },

  async scheduled(event, env, ctx) {
    // Pass scheduled events to Rust WASM
    const worker = new RustWorker(ctx, env);
    return worker.scheduled(event);
  },
};

// Re-export Rust Durable Object class implemented in WASM.
// wrangler.toml binds HEAVY_DO -> class_name = "HeavyDo".
export { HeavyDo } from "../build/index.js";

