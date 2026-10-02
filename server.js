const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");

const root = __dirname;
const envPath = path.join(root, ".env");
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, "utf8").split(/\r?\n/).forEach((line) => {
    const match = line.match(/^\s*([^#=]+?)\s*=\s*(.*?)\s*$/);
    if (!match) return;
    const name = match[1].trim();
    const value = match[2].replace(/^["']|["']$/g, "").trim();
    if (name && value && !process.env[name]) process.env[name] = value;
  });
}

const port = Number(process.env.PORT || 3000);
const novaBaseUrl = process.env.NOVA_BASE_URL || "https://www.aczen.in/nova-api/v1";
const apiKey = process.env.MY_API || "";
const authHeader = process.env.NOVA_AUTH_HEADER || "Authorization";
const authPrefix = process.env.NOVA_AUTH_PREFIX || "Bearer";
const sessionHours = 12;

const dataDir = path.join(root, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new DatabaseSync(path.join(dataDir, "ledgerguard.db"));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
`);
db.exec("PRAGMA optimize");

function sendJson(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  res.end(JSON.stringify(body));
}

function redirect(res, location) {
  res.writeHead(302, { Location: location, "Cache-Control": "no-store" });
  res.end();
}

function serveFile(res, file, type) {
  fs.readFile(file, (error, contents) => {
    if (error) return sendJson(res, 404, { error: "Page not found: " + path.basename(file) });
    res.writeHead(200, {
      "Content-Type": type,
      "Content-Length": contents.length,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    });
    res.end(contents);
  });
}

function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie || "").split(";").map((part) => {
    const index = part.indexOf("=");
    return index < 0 ? ["", ""] : [part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1))];
  }).filter(([name]) => name));
}

function tokenHash(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function currentUser(req) {
  const token = parseCookies(req).ledgerguard_session;
  if (!token) return null;
  const row = db.prepare(`
    SELECT users.id, users.name, users.email
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
  `).get(tokenHash(token), Date.now());
  return row || null;
}

function createSession(res, userId) {
  const token = crypto.randomBytes(32).toString("base64url");
  const expiresAt = Date.now() + sessionHours * 60 * 60 * 1000;
  db.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
    .run(tokenHash(token), userId, expiresAt);
  res.setHeader("Set-Cookie", `ledgerguard_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${sessionHours * 3600}`);
}

function clearSession(req, res) {
  const token = parseCookies(req).ledgerguard_session;
  if (token) db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash(token));
  res.setHeader("Set-Cookie", "ledgerguard_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 16384) {
        reject(new Error("Request is too large."));
        req.destroy();
      }
    });
    req.on("end", () => {
      try { resolve(JSON.parse(body || "{}")); }
      catch { reject(new Error("Invalid request.")); }
    });
    req.on("error", reject);
  });
}

function passwordHash(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function safePasswordCheck(password, user) {
  const supplied = Buffer.from(passwordHash(password, user.password_salt), "hex");
  const stored = Buffer.from(user.password_hash, "hex");
  return supplied.length === stored.length && crypto.timingSafeEqual(supplied, stored);
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function authRoutes(req, res, pathname) {
  if (pathname === "/api/auth/me" && req.method === "GET") {
    const user = currentUser(req);
    return sendJson(res, user ? 200 : 401, user ? { user } : { error: "Not signed in." });
  }
  if (pathname === "/api/auth/register" && req.method === "POST") {
    try {
      const body = await readJson(req);
      const name = String(body.name || "").trim().slice(0, 80);
      const email = String(body.email || "").trim().toLowerCase().slice(0, 180);
      const password = String(body.password || "");
      if (name.length < 2) return sendJson(res, 400, { error: "Enter your full name." });
      if (!validEmail(email)) return sendJson(res, 400, { error: "Enter a valid email address." });
      if (password.length < 8) return sendJson(res, 400, { error: "Password must contain at least 8 characters." });
      const salt = crypto.randomBytes(16).toString("hex");
      const result = db.prepare("INSERT INTO users (name, email, password_hash, password_salt) VALUES (?, ?, ?, ?)")
        .run(name, email, passwordHash(password, salt), salt);
      createSession(res, Number(result.lastInsertRowid));
      return sendJson(res, 201, { user: { id: Number(result.lastInsertRowid), name, email } });
    } catch (error) {
      if (String(error.message).includes("UNIQUE")) return sendJson(res, 409, { error: "An account already exists for this email." });
      return sendJson(res, 400, { error: error.message || "Registration failed." });
    }
  }
  if (pathname === "/api/auth/login" && req.method === "POST") {
    try {
      const body = await readJson(req);
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
      if (!user || !safePasswordCheck(password, user)) return sendJson(res, 401, { error: "Incorrect email or password." });
      db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(Date.now());
      createSession(res, user.id);
      return sendJson(res, 200, { user: { id: user.id, name: user.name, email: user.email } });
    } catch (error) {
      return sendJson(res, 400, { error: error.message || "Login failed." });
    }
  }
  if (pathname === "/api/auth/logout" && req.method === "POST") {
    clearSession(req, res);
    return sendJson(res, 200, { ok: true });
  }
  return false;
}

async function novaInvoices(req, res, url) {
  if (!currentUser(req)) return sendJson(res, 401, { error: "Sign in before synchronizing Nova." });
  if (!apiKey) return sendJson(res, 503, { error: "MY_API is missing in the local .env file." });
  try {
    const upstream = new URL("invoices", novaBaseUrl.endsWith("/") ? novaBaseUrl : novaBaseUrl + "/");
    upstream.searchParams.set("limit", url.searchParams.get("limit") || "5");
    const response = await fetch(upstream, {
      headers: { [authHeader]: (authPrefix ? authPrefix.trim() + " " : "") + apiKey, Accept: "application/json" }
    });
    const body = await response.text();
    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      return sendJson(res, 502, { error: "Nova returned a webpage instead of API data. Verify NOVA_BASE_URL." });
    }
    if (!response.ok) return sendJson(res, response.status, { error: "Nova rejected the request with status " + response.status + "." });
    res.writeHead(200, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
    res.end(body);
  } catch {
    sendJson(res, 502, { error: "LedgerGuard could not reach the Nova API." });
  }
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const pathname = url.pathname;
  if (pathname.startsWith("/api/auth/")) {
    const handled = await authRoutes(req, res, pathname);
    if (handled !== false) return;
  }
  if (pathname === "/api/nova/invoices") return novaInvoices(req, res, url);
  if (pathname === "/login.html") {
    if (currentUser(req)) return redirect(res, "/app");
    return serveFile(res, path.join(root, "dist", "login.html"), "text/html; charset=utf-8");
  }
  if (pathname === "/" || pathname === "/app" || pathname === "/index.html") {
    if (!currentUser(req)) return redirect(res, "/login.html");
    return serveFile(res, path.join(root, "dist", "index.html"), "text/html; charset=utf-8");
  }
  sendJson(res, 404, { error: "Not found." });
}).listen(port, () => console.log("LedgerGuard is running at http://localhost:" + port));
