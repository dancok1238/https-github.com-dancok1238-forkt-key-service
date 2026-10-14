const OAUTH_BASE = "https://apis.roblox.com/oauth";
const SESSION_SECONDS = 60 * 60 * 24 * 30;
const STATE_SECONDS = 10 * 60;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

function cookieValue(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  for (const part of cookie.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

function setCookie(name, value, maxAge, httpOnly = true) {
  return `${name}=${value}; Path=/; Max-Age=${maxAge}; Secure; SameSite=Lax${httpOnly ? "; HttpOnly" : ""}`;
}

function clearCookie(name) {
  return `${name}=; Path=/; Max-Age=0; Secure; SameSite=Lax; HttpOnly`;
}

function randomToken(bytes = 32) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return [...data].map(x => x.toString(16).padStart(2, "0")).join("");
}

function base64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function digestHex(value) {
  const data = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(data)].map(x => x.toString(16).padStart(2, "0")).join("");
}

async function pkceChallenge(verifier) {
  const data = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(data));
}

async function bodyJson(request) {
  try { return await request.json(); } catch { return null; }
}

async function getSession(request, env) {
  const raw = cookieValue(request, "fkt_session");
  if (!raw) return null;
  const sessionHash = await digestHex(raw);
  const row = await env.DB.prepare(`
    SELECT roblox_user_id, roblox_username, expires_at
    FROM sessions WHERE session_hash = ?
  `).bind(sessionHash).first();

  if (!row || row.expires_at <= Math.floor(Date.now() / 1000)) {
    if (row) {
      await env.DB.prepare("DELETE FROM sessions WHERE session_hash = ?")
        .bind(sessionHash).run();
    }
    return null;
  }
  return { id: row.roblox_user_id, username: row.roblox_username };
}

async function requireAdmin(request, env) {
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!env.ADMIN_TOKEN || token.length < 32) return false;
  const [provided, expected] = await Promise.all([
    digestHex(token), digestHex(env.ADMIN_TOKEN)
  ]);
  return provided === expected;
}

async function startLogin(request, env) {
  if (!env.ROBLOX_CLIENT_ID) return new Response("Missing ROBLOX_CLIENT_ID secret.", {status:500});
  const url = new URL(request.url);
  const redirectUri = `${url.origin}/auth/callback`;
  const state = randomToken(24);
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(48)));
  const stateHash = await digestHex(state);
  const expiresAt = Math.floor(Date.now() / 1000) + STATE_SECONDS;

  await env.DB.prepare(`
    INSERT INTO oauth_states (state_hash, verifier, expires_at) VALUES (?, ?, ?)
  `).bind(stateHash, verifier, expiresAt).run();

  const challenge = await pkceChallenge(verifier);
  const authorize = new URL(`${OAUTH_BASE}/v1/authorize`);
  authorize.searchParams.set("client_id", env.ROBLOX_CLIENT_ID);
  authorize.searchParams.set("redirect_uri", redirectUri);
  authorize.searchParams.set("scope", "openid profile");
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("code_challenge", challenge);
  authorize.searchParams.set("code_challenge_method", "S256");

  const headers = new Headers({
    "Location": authorize.toString(),
    "Cache-Control": "no-store"
  });
  headers.append("Set-Cookie", setCookie("fkt_oauth_state", state, STATE_SECONDS));
  headers.append("Set-Cookie", setCookie("fkt_oauth_verifier", verifier, STATE_SECONDS));
  return new Response(null, { status: 302, headers });
}

async function oauthCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const expectedState = cookieValue(request, "fkt_oauth_state");
  const verifierCookie = cookieValue(request, "fkt_oauth_verifier");

  const fail = (message) => {
    const headers = new Headers({
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store"
    });
    headers.append("Set-Cookie", clearCookie("fkt_oauth_state"));
    headers.append("Set-Cookie", clearCookie("fkt_oauth_verifier"));
    return new Response(
      `<!doctype html><html><meta charset="utf-8"><title>Login gagal</title><body style="font-family:system-ui;background:#111;color:#fff;padding:24px"><h2>Login Roblox gagal</h2><p>${message}</p><a style="color:#c9a5ff" href="/">Kembali</a></body></html>`,
      { status: 400, headers }
    );
  };

  if (url.searchParams.get("error")) return fail("Persetujuan login dibatalkan atau ditolak.");
  if (!code || !state || !expectedState || !verifierCookie || state !== expectedState) {
    return fail("State OAuth tidak cocok atau sesi login kedaluwarsa.");
  }

  const stateHash = await digestHex(state);
  const stateRow = await env.DB.prepare(`
    SELECT verifier, expires_at FROM oauth_states WHERE state_hash = ?
  `).bind(stateHash).first();

  if (!stateRow || stateRow.expires_at <= Math.floor(Date.now()/1000) ||
      stateRow.verifier !== verifierCookie) {
    return fail("Permintaan login sudah kedaluwarsa. Silakan coba lagi.");
  }

  await env.DB.prepare("DELETE FROM oauth_states WHERE state_hash = ?")
    .bind(stateHash).run();

  const tokenBody = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: env.ROBLOX_CLIENT_ID,
    client_secret: env.ROBLOX_CLIENT_SECRET || "",
    redirect_uri: `${url.origin}/auth/callback`,
    code_verifier: stateRow.verifier
  });

  const tokenResponse = await fetch(`${OAUTH_BASE}/v1/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: tokenBody
  });

  if (!tokenResponse.ok) return fail("Roblox tidak menerima pertukaran kode OAuth. Periksa Client ID, secret, dan Redirect URI.");
  const tokens = await tokenResponse.json();

  const infoResponse = await fetch(`${OAUTH_BASE}/v1/userinfo`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` }
  });

  if (!infoResponse.ok) return fail("Profil Roblox tidak dapat diverifikasi.");
  const info = await infoResponse.json();
  if (!info.sub) return fail("Roblox tidak mengembalikan ID akun.");

  const session = randomToken(32);
  const sessionHash = await digestHex(session);
  const now = new Date().toISOString();
  const expires = Math.floor(Date.now()/1000) + SESSION_SECONDS;

  await env.DB.prepare(`
    INSERT INTO sessions (session_hash, roblox_user_id, roblox_username, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).bind(sessionHash, String(info.sub), String(info.preferred_username || info.name || ""), expires, now).run();

  const headers = new Headers({ "Location": "/", "Cache-Control": "no-store" });
  headers.append("Set-Cookie", setCookie("fkt_session", session, SESSION_SECONDS));
  headers.append("Set-Cookie", clearCookie("fkt_oauth_state"));
  headers.append("Set-Cookie", clearCookie("fkt_oauth_verifier"));
  return new Response(null, { status: 302, headers });
}

async function issueKey(request, env) {
  const user = await getSession(request, env);
  if (!user) return json({error:"login_required", message:"Login Roblox terlebih dahulu."}, 401);

  const existing = await env.DB.prepare(`
    SELECT key_id, status, created_at FROM user_keys
    WHERE roblox_user_id = ? AND status = 'active'
  `).bind(user.id).first();

  if (existing) {
    return json({
      error: "key_record_exists",
      status: existing.status,
      key_id: existing.key_id,
      created_at: existing.created_at,
      message: existing.status === "active"
        ? "Akun ini sudah memiliki key aktif. Key asli hanya ditampilkan sekali. Jika hilang, minta admin mencabut key lama."
        : "Key lama sudah dicabut. Kamu dapat menerbitkan key baru."
    }, 409);
  }

  const key = "FKT-" + randomToken(32).toUpperCase();
  const keyId = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const keyHash = await digestHex(key);

  try {
    await env.DB.prepare(`
      INSERT INTO user_keys
        (key_id, roblox_user_id, roblox_username, key_hash, status, created_at)
      VALUES (?, ?, ?, ?, 'active', ?)
    `).bind(keyId, user.id, user.username, keyHash, createdAt).run();

    await env.DB.prepare(`
      INSERT INTO key_audit (key_id, action, actor_id, created_at)
      VALUES (?, 'issue', ?, ?)
    `).bind(keyId, user.id, createdAt).run();
  } catch {
    return json({error:"issue_failed", message:"Penerbitan gagal. Coba lagi atau hubungi admin."}, 500);
  }

  return json({
    key,
    key_id: keyId,
    status: "active",
    expires_at: null,
    message: "Simpan key sekarang. Demi keamanan, key asli hanya ditampilkan satu kali."
  }, 201);
}

async function verifyKey(request, env) {
  const body = await bodyJson(request);
  if (!body || typeof body.key !== "string" || typeof body.robloxUserId !== "string") {
    return json({valid:false, error:"invalid_request"}, 400);
  }
  if (body.key.length < 20 || body.key.length > 100 || body.robloxUserId.length > 30) {
    return json({valid:false}, 400);
  }

  const keyHash = await digestHex(body.key.trim());
  const row = await env.DB.prepare(`
    SELECT roblox_user_id, status FROM user_keys WHERE key_hash = ?
  `).bind(keyHash).first();

  const valid = Boolean(
    row &&
    row.status === "active" &&
    row.roblox_user_id === body.robloxUserId.trim()
  );

  return json({valid});
}

async function adminKeys(request, env) {
  if (!(await requireAdmin(request, env))) return json({error:"admin_unauthorized"}, 401);
  const rows = await env.DB.prepare(`
    SELECT key_id, roblox_user_id, roblox_username, status, created_at, revoked_at, revoked_by
    FROM user_keys ORDER BY created_at DESC LIMIT 500
  `).all();
  return json({keys: rows.results || []});
}

async function revokeKey(request, env) {
  if (!(await requireAdmin(request, env))) return json({error:"admin_unauthorized"}, 401);
  const body = await bodyJson(request);
  if (!body || typeof body.key_id !== "string" || body.key_id.length > 100) {
    return json({error:"key_id_required"}, 400);
  }

  const timestamp = new Date().toISOString();
  const result = await env.DB.prepare(`
    UPDATE user_keys SET status='revoked', revoked_at=?, revoked_by='admin'
    WHERE key_id=? AND status='active'
  `).bind(timestamp, body.key_id).run();

  if (!result.meta || result.meta.changes === 0) {
    return json({success:false, message:"Key tidak ditemukan atau sudah dicabut."}, 404);
  }

  await env.DB.prepare(`
    INSERT INTO key_audit (key_id, action, actor_id, created_at)
    VALUES (?, 'revoke', 'admin', ?)
  `).bind(body.key_id, timestamp).run();

  return json({success:true});
}

async function logout(request, env) {
  const raw = cookieValue(request, "fkt_session");
  if (raw) {
    await env.DB.prepare("DELETE FROM sessions WHERE session_hash=?")
      .bind(await digestHex(raw)).run();
  }
  const headers = new Headers({
    "Location": "/",
    "Cache-Control": "no-store"
  });
  headers.append("Set-Cookie", clearCookie("fkt_session"));
  return new Response(null, { status: 302, headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      return new Response(null, {status:204, headers:{
        "Allow":"GET, POST, OPTIONS",
        "Access-Control-Allow-Origin": url.origin,
        "Access-Control-Allow-Methods":"GET, POST, OPTIONS",
        "Access-Control-Allow-Headers":"Content-Type, Authorization",
        "Vary":"Origin"
      }});
    }

    try {
      if (url.pathname === "/auth/login" && request.method === "GET") return await startLogin(request, env);
      if (url.pathname === "/auth/callback" && request.method === "GET") return await oauthCallback(request, env);
      if (url.pathname === "/auth/logout" && request.method === "POST") return await logout(request, env);

      if (url.pathname === "/api/me" && request.method === "GET") {
        const user = await getSession(request, env);
        return json({loggedIn:!!user, user:user ? {id:user.id, username:user.username} : null});
      }
      if (url.pathname === "/api/issue" && request.method === "POST") return await issueKey(request, env);
      if (url.pathname === "/api/verify" && request.method === "POST") return await verifyKey(request, env);
      if (url.pathname === "/api/admin/keys" && request.method === "GET") return await adminKeys(request, env);
      if (url.pathname === "/api/revoke" && request.method === "POST") return await revokeKey(request, env);

      if (url.pathname.startsWith("/api/") || url.pathname.startsWith("/auth/")) {
        return json({error:"not_found"}, 404);
      }

      if (env.ASSETS) return env.ASSETS.fetch(request);
      return new Response("FORKT Key Service", {headers:{"Content-Type":"text/plain"}});
    } catch (error) {
      // Jangan mencetak key/token atau request body ke log.
      return json({error:"internal_error", message:"Terjadi kesalahan server."}, 500);
    }
  }
};
