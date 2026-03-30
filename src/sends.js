/**
 * Send upload/download fast-path for Warden Worker (JS)
 *
 * This module implements:
 * - Send file upload (zero-copy streaming to R2/KV)
 * - Send file download (zero-copy streaming from R2/KV)
 * - JWT validation for send tokens
 *
 * Route matching is handled by `src/entry.js`.
 */

import { base64UrlDecode } from "./attachments.js";

const JWT_EXPECTED_ALG = "HS256";
const JWT_VALIDATION_LEEWAY_SECS = 60;

async function verifyJwt(token, secret) {
  const encoder = new TextEncoder();
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid token format");

  const [headerB64, payloadB64, signatureB64] = parts;

  let header;
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64)));
  } catch {
    throw new Error("Invalid token header");
  }

  if (!header || typeof header !== "object" || header.alg !== JWT_EXPECTED_ALG) {
    throw new Error("Invalid token algorithm");
  }

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signature = base64UrlDecode(signatureB64);
  const data = encoder.encode(`${headerB64}.${payloadB64}`);
  const valid = await crypto.subtle.verify("HMAC", key, signature, data);

  if (!valid) throw new Error("Invalid token signature");

  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
  } catch {
    throw new Error("Invalid token payload");
  }

  if (!payload || typeof payload !== "object") throw new Error("Invalid token payload");
  if (typeof payload.exp !== "number") throw new Error("Invalid token exp");

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now - JWT_VALIDATION_LEEWAY_SECS) throw new Error("Token expired");

  return payload;
}

function nowString() {
  return new Date().toISOString();
}

function getStorageBackend(env) {
  if (env.ATTACHMENTS_BUCKET) return "r2";
  if (env.ATTACHMENTS_KV) return "kv";
  return null;
}

function jsonError(message, status) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * Handle Send file upload: PUT /api/sends/{sendId}/file/{fileId}/azure-upload?token=...
 */
export async function handleSendUpload(request, env, sendId, fileId, token) {
  const backend = getStorageBackend(env);
  if (!backend) return jsonError("File storage is not enabled", 400);

  const db = env.vault1;
  if (!db) return jsonError("Database not available", 500);

  let claims;
  try {
    const secret = env.JWT_SECRET?.toString?.() || env.JWT_SECRET;
    if (!secret) throw new Error("JWT_SECRET not configured");
    claims = await verifyJwt(token, secret);
  } catch (err) {
    return jsonError(`Invalid token: ${err.message}`, 401);
  }

  if (claims.send_id !== sendId || claims.file_id !== fileId) {
    return jsonError("Token claims mismatch", 401);
  }

  const userId = claims.sub;
  const contextId =
    typeof claims.device === "string" && claims.device.length > 0 ? claims.device : null;

  const pending = await db
    .prepare("SELECT * FROM sends_pending WHERE id = ?1 AND user_id = ?2")
    .bind(sendId, userId)
    .first();

  if (!pending) return jsonError("Pending send not found or already uploaded", 404);

  let pendingData;
  try {
    pendingData = JSON.parse(pending.data);
  } catch {
    return jsonError("Invalid pending send data", 500);
  }
  if (pendingData.id !== fileId) return jsonError("File ID mismatch", 400);

  const contentLengthHeader = request.headers.get("Content-Length");
  if (!contentLengthHeader) return jsonError("Missing Content-Length header", 400);

  const contentLength = parseInt(contentLengthHeader, 10);
  if (isNaN(contentLength) || contentLength <= 0) {
    return jsonError("Invalid Content-Length header", 400);
  }

  const storageKey = `sends/${sendId}/${fileId}`;
  const declaredSize = pendingData.size;
  if (typeof declaredSize !== "number" || declaredSize <= 0) {
    return jsonError("Invalid declared file size in pending send", 400);
  }

  if (contentLength !== declaredSize) {
    return jsonError(
      `Content-Length (${contentLength}) does not match declared size (${declaredSize})`,
      400
    );
  }

  if (backend === "kv") {
    const kv = env.ATTACHMENTS_KV;
    try {
      await kv.put(storageKey, request.body);
    } catch (err) {
      return jsonError(`Upload failed: ${err.message}`, 500);
    }
  } else {
    const bucket = env.ATTACHMENTS_BUCKET;
    const putOptions = {};
    const contentType = request.headers.get("Content-Type");
    if (contentType) putOptions.httpMetadata = { contentType };

    let r2Object;
    try {
      r2Object = await bucket.put(storageKey, request.body, putOptions);
    } catch (err) {
      try { await bucket.delete(storageKey); } catch { /* ignore */ }
      return jsonError(`Upload failed: ${err.message}`, 500);
    }

    if (r2Object.size !== declaredSize) {
      try { await bucket.delete(storageKey); } catch { /* ignore */ }
      return jsonError(
        `Uploaded size (${r2Object.size}) does not match declared size (${declaredSize})`,
        400
      );
    }
  }

  const fileData = JSON.stringify(pendingData);

  const now = nowString();
  await db.batch([
    db.prepare("DELETE FROM sends_pending WHERE id = ?1").bind(sendId),
    db.prepare(
      "INSERT INTO sends (id, user_id, name, notes, type, data, akey, password_hash, password_salt, password_iter, max_access_count, access_count, created_at, updated_at, expiration_date, deletion_date, disabled, hide_email) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)"
    ).bind(
      sendId,
      pending.user_id,
      pending.name,
      pending.notes,
      pending.type,
      fileData,
      pending.akey,
      pending.password_hash,
      pending.password_salt,
      pending.password_iter,
      pending.max_access_count,
      pending.access_count,
      pending.created_at,
      now,
      pending.expiration_date,
      pending.deletion_date,
      pending.disabled,
      pending.hide_email
    ),
    db.prepare("UPDATE users SET updated_at = ?1 WHERE id = ?2").bind(now, userId),
  ]);

  // Publish notification via NotifyDo
  if (env.NOTIFY_DO) {
    try {
      const id = env.NOTIFY_DO.idFromName("global");
      const stub = env.NOTIFY_DO.get(id);
      const response = await stub.fetch("https://notify.internal/publish-js-send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userId,
          updateType: 12, // SyncSendCreate
          sendId,
          payloadUserId: userId,
          revisionDate: now,
        }),
      });
      if (!response.ok) {
        console.error("NotifyDo publish failed for send upload finalize", response.status);
      }
    } catch (err) {
      console.error("NotifyDo publish threw during send upload finalize", err);
    }
  }

  return new Response(null, { status: 201 });
}

/**
 * Handle Send file download: GET /api/sends/{sendId}/{fileId}?t=...
 */
export async function handleSendDownload(request, env, sendId, fileId, token) {
  const backend = getStorageBackend(env);
  if (!backend) return jsonError("File storage is not enabled", 400);

  const db = env.vault1;
  if (!db) return jsonError("Database not available", 500);

  let claims;
  try {
    const secret = env.JWT_SECRET?.toString?.() || env.JWT_SECRET;
    if (!secret) throw new Error("JWT_SECRET not configured");
    claims = await verifyJwt(token, secret);
  } catch (err) {
    return jsonError(`Invalid token: ${err.message}`, 401);
  }

  if (claims.send_id !== sendId || claims.file_id !== fileId) {
    return jsonError("Token claims mismatch", 401);
  }

  const send = await db
    .prepare("SELECT * FROM sends WHERE id = ?1")
    .bind(sendId)
    .first();

  if (!send) return jsonError("Send not found", 404);

  const storageKey = `sends/${sendId}/${fileId}`;

  if (backend === "kv") {
    const kv = env.ATTACHMENTS_KV;
    const stream = await kv.get(storageKey, { type: "stream" });
    if (!stream) return jsonError("File not found in storage", 404);

    let fileSize = 0;
    try {
      const data = JSON.parse(send.data);
      fileSize = data.size || 0;
    } catch { /* ignore */ }

    const headers = new Headers();
    headers.set("Content-Type", "application/octet-stream");
    if (fileSize > 0) headers.set("Content-Length", fileSize.toString());

    return new Response(stream, { status: 200, headers });
  } else {
    const bucket = env.ATTACHMENTS_BUCKET;
    const r2Object = await bucket.get(storageKey);
    if (!r2Object) return jsonError("File not found in storage", 404);

    const headers = new Headers();
    const contentType = r2Object.httpMetadata?.contentType || "application/octet-stream";
    headers.set("Content-Type", contentType);
    headers.set("Content-Length", r2Object.size.toString());

    return new Response(r2Object.body, { status: 200, headers });
  }
}
