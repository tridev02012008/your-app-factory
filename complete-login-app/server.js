"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { promisify } = require("node:util");
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const sqlite3 = require("node:sqlite");
const openSessionDatabase = require("./session-db");
const scrypt = promisify(crypto.scrypt);

const app = express();
const PORT = Number(process.env.PORT ?? 3000);
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const configuredSecret = process.env.SESSION_SECRET;
if (IS_PRODUCTION && (
  !configuredSecret || Buffer.byteLength(configuredSecret) < 32 ||
  configuredSecret.includes("change-this")
)) {
  throw new Error("Production me SESSION_SECRET ke liye kam se kam 32 random bytes use karein.");
}

const dataDirectory = path.join(__dirname, "data");
const publicDirectory = path.join(__dirname, "public");

fs.mkdirSync(dataDirectory, { recursive: true, mode: 0o700 });

const database = new sqlite3.DatabaseSync(
  path.join(dataDirectory, "app.sqlite")
);

database.exec(`
  PRAGMA busy_timeout = 5000;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

function localSessionSecret() {
  database.exec("CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)");
  database.prepare(
    "INSERT OR IGNORE INTO settings (name, value) VALUES ('session_key', ?)"
  ).run(crypto.randomBytes(32).toString("hex"));
  return database.prepare("SELECT value FROM settings WHERE name = 'session_key'").get().value;
}

const SESSION_SECRET = configuredSecret || localSessionSecret();

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        formAction: ["'none'"],
        upgradeInsecureRequests: IS_PRODUCTION ? [] : null,
        baseUri: ["'none'"],
        frameAncestors: ["'none'"]
      }
    },
    crossOriginEmbedderPolicy: false
  })
);

app.use(express.json({ limit: "10kb" }));
app.disable("x-powered-by");

if (IS_PRODUCTION && process.env.TRUST_PROXY === "1") {
  app.set("trust proxy", 1);
}

app.use(
  session({
    name: "app.sid",
    store: new SQLiteStore({
      db: openSessionDatabase(path.join(dataDirectory, "sessions.sqlite"))
    }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: IS_PRODUCTION,
      sameSite: "strict",
      maxAge: 8 * 60 * 60 * 1000,
      path: "/"
    }
  })
);

app.use("/api", (_request, response, next) => {
  response.set("Cache-Control", "no-store");
  next();
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "Bahut saari koshishein hui hain. 15 minute baad try karein."
  }
});

function createCsrfToken() {
  return crypto.randomBytes(32).toString("hex");
}

function csrfMatches(expected, received) {
  if (
    typeof expected !== "string" ||
    typeof received !== "string"
  ) {
    return false;
  }

  const expectedBuffer = Buffer.from(expected);
  const receivedBuffer = Buffer.from(received);

  return (
    expectedBuffer.length === receivedBuffer.length &&
    crypto.timingSafeEqual(expectedBuffer, receivedBuffer)
  );
}

function requireCsrf(request, response, next) {
  if (!csrfMatches(
    request.session.csrfToken,
    request.get("X-CSRF-Token")
  )) {
    return response.status(403).json({
      code: "CSRF",
      error: "Request verify nahi hui. Page reload karke dobara try karein."
    });
  }

  next();
}

function validUsername(username) {
  return (
    typeof username === "string" &&
    /^[A-Za-z0-9_]{3,32}$/.test(username)
  );
}

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 12 &&
    password.length <= 200
  );
}

// bcrypt handles the shorter inputs. For longer UTF-8 input, verify the entire password.
async function longPasswordKey(password, salt) {
  return scrypt(password, salt, 32, { N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 });
}

async function hashPassword(password) {
  if (Buffer.byteLength(password, "utf8") <= 72) return bcrypt.hash(password, 12);
  const salt = crypto.randomBytes(16);
  const key = await longPasswordKey(password, salt);
  return `scrypt-v1$${salt.toString("hex")}$${key.toString("hex")}`;
}

async function matchesPassword(password, stored) {
  if (!stored.startsWith("scrypt-v1$")) return bcrypt.compare(password, stored);
  const [, saltHex, keyHex] = stored.split("$");
  const expected = Buffer.from(keyHex, "hex");
  const actual = await longPasswordKey(password, Buffer.from(saltHex, "hex"));
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function findUserById(id) {
  return database
    .prepare("SELECT id, username FROM users WHERE id = ?")
    .get(id);
}

function establishSession(request, response, user) {
  request.session.regenerate((regenerateError) => {
    if (regenerateError) {
      console.error(regenerateError);
      return response.status(500).json({
        error: "Session banane me dikkat hui."
      });
    }

    request.session.userId = user.id;
    request.session.csrfToken = createCsrfToken();

    request.session.save((saveError) => {
      if (saveError) {
        console.error(saveError);
        return response.status(500).json({
          error: "Session save nahi ho saka."
        });
      }

      response.json({
        csrfToken: request.session.csrfToken,
        user: {
          id: user.id,
          username: user.username
        }
      });
    });
  });
}

// Frontend ke liye CSRF token.
app.get("/api/csrf", (request, response) => {
  if (!request.session.csrfToken) {
    request.session.csrfToken = createCsrfToken();
  }

  response.json({
    csrfToken: request.session.csrfToken
  });
});

// Current logged-in user.
app.get("/api/me", (request, response) => {
  if (!request.session.userId) {
    return response.json({ user: null });
  }

  const user = findUserById(request.session.userId);

  if (!user) {
    return request.session.destroy(() => {
      response.json({ user: null });
    });
  }

  response.json({
    user: {
      id: user.id,
      username: user.username
    }
  });
});

// Naya account.
app.post(
  "/api/register",
  loginLimiter,
  requireCsrf,
  async (request, response) => {
    const username = request.body?.username;
    const password = request.body?.password;

    if (!validUsername(username)) {
      return response.status(400).json({
        error:
          "Username 3-32 characters ka ho aur sirf letters, numbers ya underscore ho."
      });
    }

    if (!validPassword(password)) {
      return response.status(400).json({
        error: "Password 12 se 200 characters ka hona chahiye."
      });
    }

    try {
      const passwordHash = await hashPassword(password);

      const result = database
        .prepare(
          "INSERT INTO users (username, password_hash) VALUES (?, ?)"
        )
        .run(username, passwordHash);

      establishSession(request, response, {
        id: Number(result.lastInsertRowid),
        username
      });
    } catch (error) {
      if (String(error.message).includes("UNIQUE")) {
        return response.status(409).json({
          error: "Yeh username pehle se registered hai."
        });
      }

      console.error(error);
      response.status(500).json({
        error: "Account create nahi ho saka."
      });
    }
  }
);

// Account login.
app.post(
  "/api/login",
  loginLimiter,
  requireCsrf,
  async (request, response) => {
    const username = request.body?.username;
    const password = request.body?.password;

    if (
      typeof username !== "string" ||
      typeof password !== "string"
    ) {
      return response.status(400).json({
        error: "Username aur password daalein."
      });
    }

    try {
      const user = database
        .prepare(
          `SELECT id, username, password_hash
           FROM users
           WHERE username = ?`
        )
        .get(username);

      const passwordMatches =
        Boolean(user) &&
        await matchesPassword(password, user.password_hash);

      if (!passwordMatches) {
        return response.status(401).json({
          error: "Username ya password galat hai."
        });
      }

      establishSession(request, response, user);
    } catch (error) {
      console.error(error);
      response.status(500).json({
        error: "Login process nahi ho saka."
      });
    }
  }
);

// Logout.
app.post("/api/logout", requireCsrf, (request, response) => {
  request.session.destroy((error) => {
    if (error) {
      console.error(error);
      return response.status(500).json({
        error: "Logout nahi ho saka."
      });
    }

    response.clearCookie("app.sid", {
      httpOnly: true,
      secure: IS_PRODUCTION,
      sameSite: "strict",
      path: "/"
    });

    response.json({ ok: true });
  });
});

app.use(express.static(publicDirectory));

const host = IS_PRODUCTION ? "0.0.0.0" : "127.0.0.1";
const listener = app.listen(PORT, host, () => {
  console.log(`Server: http://${host}:${listener.address().port}`);
});
