/**
 * Cloudflare Worker: Zero-Cost User Authentication (Email/Password via D1) +
 * Anti-Piracy HLS Key & Playlist Gatekeeper for R2 Video Streaming.
 *
 * Required Bindings in Cloudflare Dashboard (Workers -> Settings -> Bindings):
 * 1. D1 Database Binding : DB          (Stores users & course/video access permissions)
 * 2. R2 Bucket Binding   : VIDEO_BUCKET (Your PRIVATE R2 bucket storing secret.key, index.m3u8, and .ts segments)
 * 3. Environment Variable: JWT_SECRET   (A strong random secret string for signing tokens)
 * 4. Environment Variable: ALLOWED_ORIGIN (e.g., "https://yourdomain.com" or "http://localhost:8080" for testing)
 *
 * D1 SQL Schema (Run once in Cloudflare D1 Console):
 * CREATE TABLE users (
 *   id INTEGER PRIMARY KEY AUTOINCREMENT,
 *   email TEXT UNIQUE NOT NULL,
 *   password_hash TEXT NOT NULL,
 *   has_access INTEGER DEFAULT 1
 * );
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const allowedOrigin = env.ALLOWED_ORIGIN || "*";
    const origin = request.headers.get("Origin") || "";

    // 1. Handle CORS Preflight Requests
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: getCorsHeaders(allowedOrigin),
      });
    }

    // 2. Block CLI Downloaders & Scrapers (yt-dlp, ffmpeg, IDM, curl, wget)
    const userAgent = (request.headers.get("User-Agent") || "").toLowerCase();
    const blockedAgents = ["yt-dlp", "youtube-dl", "ffmpeg", "lavf", "idm", "curl", "wget", "python-requests", "aria2"];
    if (blockedAgents.some((bot) => userAgent.includes(bot))) {
      return jsonResponse({ error: "Downloader tools are not permitted." }, 403, allowedOrigin);
    }

    // 3. Route: POST /api/register (Create user account in D1)
    if (url.pathname === "/api/register" && request.method === "POST") {
      const { email, password } = await request.json();
      if (!email || !password) {
        return jsonResponse({ error: "Email and password required" }, 400, allowedOrigin);
      }
      const passwordHash = await sha256Hex(password + ":" + env.JWT_SECRET);
      try {
        await env.DB.prepare("INSERT INTO users (email, password_hash, has_access) VALUES (?1, ?2, 1)")
          .bind(email.toLowerCase().trim(), passwordHash)
          .run();
        return jsonResponse({ message: "User registered" }, 201, allowedOrigin);
      } catch (e) {
        return jsonResponse({ error: "User already exists" }, 409, allowedOrigin);
      }
    }

    // 4. Route: POST /api/login (Authenticate email & password -> Return IP-bound JWT)
    if (url.pathname === "/api/login" && request.method === "POST") {
      const { email, password } = await request.json();
      const passwordHash = await sha256Hex(password + ":" + env.JWT_SECRET);

      const user = await env.DB.prepare(
        "SELECT id, email, has_access FROM users WHERE email = ?1 AND password_hash = ?2"
      )
        .bind((email || "").toLowerCase().trim(), passwordHash)
        .first();

      if (!user) {
        return jsonResponse({ error: "Invalid email or password" }, 401, allowedOrigin);
      }
      if (!user.has_access) {
        return jsonResponse({ error: "Your account does not have access to this video" }, 403, allowedOrigin);
      }

      const clientIp = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
      const token = await signJwt(
        {
          sub: user.id,
          email: user.email,
          ip: clientIp,
          exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour expiry
        },
        env.JWT_SECRET
      );

      return jsonResponse({ token, email: user.email }, 200, allowedOrigin);
    }

    // 5. Protected Video Routes: /video/<videoId>/index.m3u8, /video/<videoId>/secret.key, /video/<videoId>/segment_xxx.ts
    if (url.pathname.startsWith("/video/")) {
      // Enforce Origin / Referer domain check when ALLOWED_ORIGIN is set
      if (allowedOrigin !== "*" && origin !== allowedOrigin) {
        return jsonResponse({ error: "Unauthorized domain origin" }, 403, allowedOrigin);
      }

      // Extract & verify Bearer JWT from Authorization header
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
      const payload = await verifyJwt(token, env.JWT_SECRET);

      if (!payload) {
        return jsonResponse({ error: "Invalid or expired session token" }, 401, allowedOrigin);
      }

      // Verify token IP matches current viewer's IP (prevents sharing token links with others)
      const clientIp = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
      if (payload.ip !== clientIp) {
        return jsonResponse({ error: "Session IP mismatch" }, 403, allowedOrigin);
      }

      // Map URL path "/video/video-01/secret.key" -> R2 object key "videos/video-01/secret.key"
      const objectKey = "videos/" + url.pathname.replace(/^\/video\//, "");

      // Prevent direct browser navigation to secret.key unless requested via XHR/Fetch
      if (objectKey.endsWith(".key")) {
        const secFetchDest = request.headers.get("Sec-Fetch-Dest") || "";
        if (secFetchDest === "document") {
          return jsonResponse({ error: "Direct key download forbidden" }, 403, allowedOrigin);
        }
      }

      const object = await env.VIDEO_BUCKET.get(objectKey);
      if (!object) {
        return jsonResponse({ error: "File not found" }, 404, allowedOrigin);
      }

      const headers = new Headers(getCorsHeaders(allowedOrigin));
      if (objectKey.endsWith(".m3u8")) {
        headers.set("Content-Type", "application/vnd.apple.mpegurl");
        headers.set("Cache-Control", "no-store");
      } else if (objectKey.endsWith(".key")) {
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Cache-Control", "no-store, no-cache, must-revalidate");
      } else if (objectKey.endsWith(".ts")) {
        headers.set("Content-Type", "video/mp2t");
        headers.set("Cache-Control", "public, max-age=86400");
      }

      return new Response(object.body, { status: 200, headers });
    }

    return jsonResponse({ error: "Not found" }, 404, allowedOrigin);
  },
};

/* --- Helper Functions (Web Crypto API - Zero Dependencies) --- */

function getCorsHeaders(allowedOrigin) {
  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Range",
    "Access-Control-Expose-Headers": "Content-Length, Content-Range",
  };
}

function jsonResponse(data, status, allowedOrigin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...getCorsHeaders(allowedOrigin),
    },
  });
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function base64UrlEncode(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return atob(str);
}

async function signJwt(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const encHeader = base64UrlEncode(JSON.stringify(header));
  const encPayload = base64UrlEncode(JSON.stringify(payload));
  const data = `${encHeader}.${encPayload}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const encSig = base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
  return `${data}.${encSig}`;
}

async function verifyJwt(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [encHeader, encPayload, encSig] = parts;
    const data = `${encHeader}.${encPayload}`;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const sigBytes = Uint8Array.from(base64UrlDecode(encSig), (c) => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(data));
    if (!isValid) return null;

    const payload = JSON.parse(base64UrlDecode(encPayload));
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}