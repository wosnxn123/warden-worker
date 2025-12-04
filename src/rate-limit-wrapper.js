/**
 * Rate Limiting Wrapper for Warden Worker
 *
 * This wrapper intercepts requests before they reach the Rust WASM handler,
 * applying rate limiting to sensitive endpoints using Cloudflare's Rate Limiting API.
 *
 * Rate limiting is applied to:
 * - /identity/connect/token (login attempts)
 * - /api/accounts/register (registration attempts)
 * - /api/accounts/prelogin (prelogin attempts)
 *
 * The rate limit key is based on:
 * - For login: email address (from request body)
 * - For other endpoints: IP address (from cf-connecting-ip header)
 */

import WasmWorker from "../build/index.js";

// Endpoints that require rate limiting
const RATE_LIMITED_ENDPOINTS = {
  "/identity/connect/token": {
    limiter: "LOGIN_RATE_LIMITER",
    keyType: "email", // Use email from request body as key
  },
  "/api/accounts/register": {
    limiter: "LOGIN_RATE_LIMITER",
    keyType: "ip",
  },
  "/api/accounts/prelogin": {
    limiter: "LOGIN_RATE_LIMITER",
    keyType: "ip",
  },
};

/**
 * Extract the rate limit key from the request
 * @param {Request} request - The incoming request
 * @param {string} keyType - Type of key to extract ('email' or 'ip')
 * @returns {Promise<string>} - The rate limit key
 */
async function extractRateLimitKey(request, keyType) {
  if (keyType === "email") {
    try {
      // Clone the request to read the body without consuming it
      const clonedRequest = request.clone();
      const contentType = request.headers.get("content-type") || "";

      if (contentType.includes("application/x-www-form-urlencoded")) {
        const formData = await clonedRequest.formData();
        const username = formData.get("username");
        if (username) {
          return `email:${username.toLowerCase()}`;
        }
      } else if (contentType.includes("application/json")) {
        const body = await clonedRequest.json();
        const email = body.email || body.username;
        if (email) {
          return `email:${email.toLowerCase()}`;
        }
      }
    } catch (e) {
      console.warn("Failed to extract email from request body:", e);
    }
  }

  // Fall back to IP address
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  return `ip:${ip}`;
}

/**
 * Check if the request should be rate limited
 * @param {Request} request - The incoming request
 * @param {Object} env - The environment bindings
 * @returns {Promise<{limited: boolean, key: string, endpoint: string} | null>}
 */
async function checkRateLimit(request, env) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // Find matching endpoint
  const endpointConfig = RATE_LIMITED_ENDPOINTS[pathname];
  if (!endpointConfig) {
    return null; // Not a rate-limited endpoint
  }

  // Check if the rate limiter binding exists
  const limiter = env[endpointConfig.limiter];
  if (!limiter) {
    console.warn(
      `Rate limiter binding '${endpointConfig.limiter}' not found, skipping rate limit check`
    );
    return null;
  }

  // Extract the rate limit key
  const key = await extractRateLimitKey(request, endpointConfig.keyType);

  // Check rate limit
  try {
    const { success } = await limiter.limit({ key });
    return {
      limited: !success,
      key,
      endpoint: pathname,
    };
  } catch (e) {
    console.error("Rate limit check failed:", e);
    return null; // On error, allow the request through
  }
}

/**
 * Create a 429 Too Many Requests response
 * @param {string} key - The rate limit key that was exceeded
 * @param {string} endpoint - The endpoint that was rate limited
 * @returns {Response}
 */
function createRateLimitResponse(key, endpoint) {
  // Bitwarden-compatible error response
  const errorResponse = {
    error: "too_many_requests",
    error_description: "Too many requests. Please try again later.",
    ErrorModel: {
      Message: "Too many requests. Please try again later.",
      Object: "error",
    },
  };

  console.warn(`Rate limit exceeded for ${endpoint}, key: ${key}`);

  return new Response(JSON.stringify(errorResponse), {
    status: 429,
    headers: {
      "Content-Type": "application/json",
      "Retry-After": "60",
    },
  });
}

// Create a single instance of the WASM worker to reuse
let wasmWorkerInstance = null;

function getWasmWorker(env, ctx) {
  // Create a new instance with the current env and ctx
  // WorkerEntrypoint classes expect env and ctx to be set
  const instance = new WasmWorker(ctx, env);
  return instance;
}

export default {
  async fetch(request, env, ctx) {
    // Check rate limit for sensitive endpoints
    const rateLimitResult = await checkRateLimit(request, env);

    if (rateLimitResult?.limited) {
      return createRateLimitResponse(
        rateLimitResult.key,
        rateLimitResult.endpoint
      );
    }

    // Create WASM worker instance and forward the request
    const wasmWorker = getWasmWorker(env, ctx);
    return wasmWorker.fetch(request);
  },

  async scheduled(event, env, ctx) {
    // Create WASM worker instance and forward the scheduled event
    const wasmWorker = getWasmWorker(env, ctx);
    return wasmWorker.scheduled(event);
  },
};
