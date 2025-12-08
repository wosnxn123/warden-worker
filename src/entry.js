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
 * All other requests are passed through to the Rust WASM module.
 */

import RustWorker from "../build/index.js";

// JWT validation using Web Crypto API (no external dependencies)
async function verifyJWT(token, secret) {
  const encoder = new TextEncoder();
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid token format");
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  // Import the secret key for HMAC-SHA256
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  // Decode the signature (base64url to Uint8Array)
  const signature = base64UrlDecode(signatureB64);

  // Verify the signature
  const data = encoder.encode(`${headerB64}.${payloadB64}`);
  const valid = await crypto.subtle.verify("HMAC", key, signature, data);

  if (!valid) {
    throw new Error("Invalid token signature");
  }

  // Decode and parse the payload
  const payload = JSON.parse(
    new TextDecoder().decode(base64UrlDecode(payloadB64))
  );

  // Check expiration
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("Token expired");
  }

  return payload;
}

function base64UrlDecode(str) {
  // Convert base64url to base64
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding if needed
  while (base64.length % 4) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
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

// Extract token from query string
function extractTokenFromQuery(url) {
  const params = new URL(url).searchParams;
  return params.get("token");
}

// Generate ISO timestamp string
function nowString() {
  return new Date().toISOString();
}

// Helper to get env var with fallback
function getEnvVar(env, name, defaultValue = null) {
  try {
    const value = env[name];
    if (value && typeof value.toString === "function") {
      return value.toString();
    }
    return value || defaultValue;
  } catch {
    return defaultValue;
  }
}

// Get attachment size limits from env
function getAttachmentMaxBytes(env) {
  const value = getEnvVar(env, "ATTACHMENT_MAX_BYTES");
  if (!value) return null;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? null : parsed;
}

function getTotalLimitBytes(env) {
  const value = getEnvVar(env, "ATTACHMENT_TOTAL_LIMIT_KB");
  if (!value) return null;
  const kb = parseInt(value, 10);
  if (isNaN(kb)) return null;
  return kb * 1024;
}

// Get user's current attachment usage
async function getUserAttachmentUsage(db, userId, excludeAttachmentId) {
  const query = excludeAttachmentId
    ? `SELECT COALESCE(SUM(a.file_size), 0) as total
       FROM attachments a
       JOIN ciphers c ON c.id = a.cipher_id
       WHERE c.user_id = ?1 AND a.id != ?2`
    : `SELECT COALESCE(SUM(a.file_size), 0) as total
       FROM attachments a
       JOIN ciphers c ON c.id = a.cipher_id
       WHERE c.user_id = ?1`;

  const bindings = excludeAttachmentId ? [userId, excludeAttachmentId] : [userId];

  const result = await db
    .prepare(query)
    .bind(...bindings)
    .first();

  return result?.total || 0;
}

// Enforce attachment size limits
async function enforceLimits(db, env, userId, newSize, excludeAttachmentId) {
  if (newSize < 0) {
    throw new Error("Attachment size cannot be negative");
  }

  const maxBytes = getAttachmentMaxBytes(env);
  if (maxBytes !== null && newSize > maxBytes) {
    throw new Error("Attachment size exceeds limit");
  }

  const limitBytes = getTotalLimitBytes(env);
  if (limitBytes !== null) {
    const used = await getUserAttachmentUsage(db, userId, excludeAttachmentId);
    const newTotal = used + newSize;
    if (newTotal > limitBytes) {
      throw new Error("Attachment storage limit reached");
    }
  }
}

// Handle azure-upload with zero-copy streaming
async function handleAzureUpload(request, env, cipherId, attachmentId, token) {
  // Get R2 bucket
  const bucket = env.ATTACHMENTS_BUCKET;
  if (!bucket) {
    return new Response(JSON.stringify({ error: "Attachments are not enabled" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Get D1 database
  const db = env.vault1;
  if (!db) {
    return new Response(JSON.stringify({ error: "Database not available" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Validate JWT token
  let claims;
  try {
    const secret = env.JWT_SECRET?.toString?.() || env.JWT_SECRET;
    if (!secret) {
      throw new Error("JWT_SECRET not configured");
    }
    claims = await verifyJWT(token, secret);
  } catch (err) {
    return new Response(JSON.stringify({ error: `Invalid token: ${err.message}` }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Validate token claims match the request
  if (claims.cipher_id !== cipherId || claims.attachment_id !== attachmentId) {
    return new Response(JSON.stringify({ error: "Invalid download token" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const userId = claims.sub;

  // Verify cipher belongs to user and is not deleted
  const cipher = await db
    .prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
    .bind(cipherId, userId)
    .first();

  if (!cipher) {
    return new Response(JSON.stringify({ error: "Cipher not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (cipher.organization_id) {
    return new Response(
      JSON.stringify({ error: "Organization attachments are not supported" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  if (cipher.deleted_at) {
    return new Response(
      JSON.stringify({ error: "Cannot modify attachments for deleted cipher" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  // Fetch attachment record
  const attachment = await db
    .prepare("SELECT * FROM attachments WHERE id = ?1")
    .bind(attachmentId)
    .first();

  if (!attachment) {
    return new Response(JSON.stringify({ error: "Attachment not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (attachment.cipher_id !== cipherId) {
    return new Response(
      JSON.stringify({ error: "Attachment does not belong to cipher" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  // Get Content-Length from request headers
  const contentLengthHeader = request.headers.get("Content-Length");
  if (!contentLengthHeader) {
    return new Response(
      JSON.stringify({ error: "Missing Content-Length header" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  const contentLength = parseInt(contentLengthHeader, 10);
  if (isNaN(contentLength) || contentLength <= 0) {
    return new Response(
      JSON.stringify({ error: "Invalid Content-Length header" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  // Enforce limits before upload
  try {
    await enforceLimits(db, env, userId, contentLength, attachmentId);
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Build R2 key
  const r2Key = `${cipherId}/${attachmentId}`;

  // Prepare R2 put options
  const putOptions = {};
  const contentType = request.headers.get("Content-Type");
  if (contentType) {
    putOptions.httpMetadata = { contentType };
  }

  // Upload to R2 directly using request.body
  // Workers R2 binding can accept request.body directly for zero-copy streaming
  // See: https://blog.cloudflare.com/zh-cn/r2-ga/
  let r2Object;
  try {
    r2Object = await bucket.put(r2Key, request.body, putOptions);
  } catch (err) {
    // Try to clean up on failure
    try {
      await bucket.delete(r2Key);
    } catch {
      // Ignore cleanup errors
    }
    return new Response(
      JSON.stringify({ error: `Upload failed: ${err.message}` }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }

  const uploadedSize = r2Object.size;

  // Verify uploaded size matches Content-Length
  if (uploadedSize !== contentLength) {
    try {
      await bucket.delete(r2Key);
    } catch {
      // Ignore cleanup errors
    }
    return new Response(
      JSON.stringify({ error: "Content-Length does not match uploaded size" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  // Re-enforce limits with actual uploaded size (should be same, but be safe)
  try {
    await enforceLimits(db, env, userId, uploadedSize, attachmentId);
  } catch (err) {
    try {
      await bucket.delete(r2Key);
    } catch {
      // Ignore cleanup errors
    }
    return new Response(JSON.stringify({ error: err.message }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Update attachment record in database
  const now = nowString();
  await db
    .prepare("UPDATE attachments SET file_size = ?1, updated_at = ?2 WHERE id = ?3")
    .bind(uploadedSize, now, attachmentId)
    .run();

  // Touch cipher updated_at
  await db
    .prepare("UPDATE ciphers SET updated_at = ?1 WHERE id = ?2")
    .bind(now, cipherId)
    .run();

  // Touch user updated_at
  await db
    .prepare("UPDATE users SET updated_at = ?1 WHERE id = ?2")
    .bind(now, userId)
    .run();

  return new Response(null, { status: 201 });
}

// Handle download with zero-copy streaming
async function handleDownload(request, env, cipherId, attachmentId, token) {
  // Get R2 bucket
  const bucket = env.ATTACHMENTS_BUCKET;
  if (!bucket) {
    return new Response(JSON.stringify({ error: "Attachments are not enabled" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Get D1 database
  const db = env.vault1;
  if (!db) {
    return new Response(JSON.stringify({ error: "Database not available" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Validate JWT token
  let claims;
  try {
    const secret = env.JWT_SECRET?.toString?.() || env.JWT_SECRET;
    if (!secret) {
      throw new Error("JWT_SECRET not configured");
    }
    claims = await verifyJWT(token, secret);
  } catch (err) {
    return new Response(JSON.stringify({ error: `Invalid token: ${err.message}` }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Validate token claims match the request
  if (claims.cipher_id !== cipherId || claims.attachment_id !== attachmentId) {
    return new Response(JSON.stringify({ error: "Invalid download token" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const userId = claims.sub;

  // Verify cipher belongs to user
  const cipher = await db
    .prepare("SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2")
    .bind(cipherId, userId)
    .first();

  if (!cipher) {
    return new Response(JSON.stringify({ error: "Cipher not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Fetch attachment record
  const attachment = await db
    .prepare("SELECT * FROM attachments WHERE id = ?1")
    .bind(attachmentId)
    .first();

  if (!attachment) {
    return new Response(JSON.stringify({ error: "Attachment not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (attachment.cipher_id !== cipherId) {
    return new Response(
      JSON.stringify({ error: "Attachment does not belong to cipher" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  // Build R2 key
  const r2Key = `${cipherId}/${attachmentId}`;

  // Get object from R2
  const r2Object = await bucket.get(r2Key);
  if (!r2Object) {
    return new Response(JSON.stringify({ error: "Attachment not found in storage" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Build response headers
  const headers = new Headers();
  const contentType = r2Object.httpMetadata?.contentType || "application/octet-stream";
  headers.set("Content-Type", contentType);
  headers.set("Content-Length", r2Object.size.toString());

  // Return response with R2 object body directly - zero-copy streaming!
  // The Workers runtime streams the body directly to the client without consuming CPU time
  return new Response(r2Object.body, {
    status: 200,
    headers,
  });
}

// Main fetch handler
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Intercept PUT requests to azure-upload endpoint
    if (request.method === "PUT") {
      const parsed = parseAzureUploadPath(url.pathname);
      if (parsed) {
        const token = extractTokenFromQuery(request.url);
        if (token) {
          return handleAzureUpload(
            request,
            env,
            parsed.cipherId,
            parsed.attachmentId,
            token
          );
        }
      }
    }

    // Intercept GET requests to download endpoint for zero-copy streaming
    if (request.method === "GET") {
      const parsed = parseDownloadPath(url.pathname);
      if (parsed) {
        const token = extractTokenFromQuery(request.url);
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

