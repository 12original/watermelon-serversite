// server.js — справжній бекенд адмін-панелі Watermelon (Node.js + Express)
// Деплой: Render (той самий сервіс, що вже є за адресою watermelon-serversite.onrender.com)
//
// Що виправлено порівняно з попередньою версією:
//   1) IP тепер визначає СЕРВЕР (з заголовків реального запиту), а не клієнт —
//      раніше фронтенд надсилав фейковий рядок "auto", тому в таблиці й не
//      було нормальних адрес.
//   2) GET і DELETE тепер вимагають реальний токен адміна. Пароль перевіряється
//      ОДИН РАЗ на /api/login і ніколи не повертається назад клієнту — замість
//      нього видається тимчасовий токен сесії. Раніше пароль лежав відкрито в
//      коді сайту, і GET/DELETE взагалі не перевірялись на сервері (будь-хто
//      міг напряму дернути API і побачити/стерти лог відвідувачів).
//
// Змінні середовища (Render → Settings → Environment):
//   ADMIN_PASSWORD   — пароль адмінки (обов'язково задай, інакше вхід буде вимкнено)
//   ALLOWED_ORIGIN    — (необов'язково) домен твого сайту для CORS, напр.
//                        "https://watermelon.example.com". Якщо не задано — дозволено з будь-якого.

const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.set("trust proxy", true); // Render стоїть за проксі — без цього req.ip буде адресою проксі, а не відвідувача

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";
const DATA_FILE = path.join(__dirname, "data", "visitors.json");
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 годин
const MAX_LOGS = 1000;

// ---------- CORS ----------
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.json());

// ---------- Просте файлове сховище (JSON) ----------
function ensureDataFile() {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, "[]", "utf8");
}
function readLogs() {
  ensureDataFile();
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}
function writeLogs(logs) {
  ensureDataFile();
  fs.writeFileSync(DATA_FILE, JSON.stringify(logs.slice(-MAX_LOGS), null, 0), "utf8");
}

// ---------- Токени сесій адміна (в пам'яті процесу) ----------
// Примітка: на безкоштовному Render сервіс може "заснути" при простої й
// перезапуститись при новому запиті — тоді всі токени зникнуть і треба
// буде залогінитись у панелі ще раз. Для лічильника відвідувань невеликого
// Discord-сайту це прийнятний компроміс і не потребує окремої бази даних.
const sessions = new Map(); // token -> expiresAt (ms)

function createSession() {
  const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, Date.now() + SESSION_TTL_MS);
  return token;
}
function isValidToken(token) {
  if (!token) return false;
  const expiresAt = sessions.get(token);
  if (!expiresAt) return false;
  if (Date.now() > expiresAt) { sessions.delete(token); return false; }
  return true;
}
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!isValidToken(token)) return res.status(401).json({ success: false, error: "unauthorized" });
  next();
}

// ---------- Реальна IP-адреса відвідувача ----------
function getRealIp(req) {
  // req.ip вже враховує X-Forwarded-For завдяки "trust proxy" вище.
  let ip = req.ip || req.socket.remoteAddress || "unknown";
  if (ip.startsWith("::ffff:")) ip = ip.slice(7); // IPv4-mapped IPv6 -> звичайний вигляд
  return ip;
}

function calculateStatus(logs, ip, timestamp) {
  const oneMinAgo = timestamp - 60000;
  const recent = logs.filter((e) => e.ip === ip && e.timestamp >= oneMinAgo);
  if (recent.length > 15) return "🚨 DDoS";
  if (recent.length > 5) return "⚠️ підозріло";
  return "норма";
}

// ---------- Публічний ендпоінт: логування візиту ----------
app.post("/api/logs", (req, res) => {
  const body = req.body || {};
  const now = Date.now();
  const ip = getRealIp(req); // ← ігноруємо будь-яке "ip" з тіла запиту, беремо реальну адресу
  const logs = readLogs();
  const entry = {
    time: new Date(now).toLocaleString("uk-UA"),
    ip,
    browser: body.browser || "unknown",
    os: body.os || "unknown",
    screen: body.screen || "—",
    page: body.page || "/",
    timestamp: now,
  };
  entry.status = calculateStatus(logs, ip, now);
  logs.push(entry);
  writeLogs(logs);
  res.json({ success: true });
});

// ---------- Логін адміна ----------
app.post("/api/login", (req, res) => {
  const { password } = req.body || {};
  if (!ADMIN_PASSWORD) {
    return res.status(500).json({ success: false, error: "server_not_configured" });
  }
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ success: false, error: "wrong_password" });
  }
  const token = createSession();
  res.json({ success: true, token, expiresInMs: SESSION_TTL_MS });
});

// ---------- Список візитів (лише для залогіненого адміна) ----------
app.get("/api/logs", requireAuth, (req, res) => {
  res.json(readLogs());
});

// ---------- Очистити лог (лише для залогіненого адміна) ----------
app.delete("/api/logs", requireAuth, (req, res) => {
  writeLogs([]);
  res.json({ success: true });
});

app.get("/", (req, res) => {
  res.json({ ok: true, service: "watermelon-admin-backend" });
});

app.listen(PORT, () => {
  console.log("Watermelon backend running on port " + PORT);
  if (!ADMIN_PASSWORD) {
    console.warn("УВАГА: змінна середовища ADMIN_PASSWORD не задана — вхід в адмінку буде неможливий, поки її не додаси в Render → Environment.");
  }
});
