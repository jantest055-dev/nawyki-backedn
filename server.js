require("dotenv").config();
const express = require("express");
const cors    = require("cors");
const bcrypt  = require("bcryptjs");
const jwt     = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto  = require("crypto");
const fs      = require("fs");
const path    = require("path");

const app = express();
app.use(cors());
app.use(express.json());

// ── BAZA DANYCH (plik JSON) ───────────────────────────────────────────────────
const DB_FILE = path.join(__dirname, "db.json");

function loadDB() {
  if (!fs.existsSync(DB_FILE)) return { users: {} };
  try { return JSON.parse(fs.readFileSync(DB_FILE, "utf8")); }
  catch { return { users: {} }; }
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), "utf8");
}

// ── CONFIG ────────────────────────────────────────────────────────────────────
const JWT_SECRET    = process.env.JWT_SECRET || "dev_secret_change_me";
const PORT          = process.env.PORT || 3000;
const PREMIUM_CODES = (process.env.PREMIUM_CODES || "WOJOWNIK2024,DYSCYPLINA77,NAWYKI2024,KOD77")
  .split(",").map(c => c.trim().toUpperCase());

// ── MAILER (opcjonalny) ───────────────────────────────────────────────────────
const mailerEnabled = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
const transporter   = mailerEnabled
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT) || 587,
      secure: false,
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;

async function sendVerificationEmail(email, token) {
  if (!transporter) return;
  const url = `${process.env.FRONTEND_URL || "http://localhost:5173"}/verify?token=${token}`;
  await transporter.sendMail({
    from: process.env.FROM_EMAIL || "Nawyki Wojownika <noreply@example.com>",
    to: email,
    subject: "Aktywuj konto — Nawyki Wojownika",
    html: `<div style="font-family:sans-serif">
      <h2 style="color:#f0a500">⚔️ Nawyki Wojownika</h2>
      <p>Kliknij link żeby aktywować konto:</p>
      <a href="${url}" style="padding:12px 24px;background:#f0a500;color:#000;text-decoration:none;border-radius:8px;font-weight:700">AKTYWUJ →</a>
    </div>`,
  });
}

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return res.status(401).json({ message: "Brak tokenu." });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Token nieważny lub wygasł." });
  }
}

// ── HELPER ────────────────────────────────────────────────────────────────────
function buildMe(user) {
  const d = user.data || {};
  return {
    id:          user.id,
    name:        user.name,
    email:       user.email,
    is_premium:  !!user.is_premium,
    is_verified: !!user.is_verified,
    xp:          d.xp        || 0,
    streak:      d.streak    || 1,
    tasks:       d.tasks     || [],
    lessons:     d.lessons   || [],
    challenges:  d.challenges|| {},
    history:     d.history   || {},
    lastDay:     d.lastDay   || null,
    onboarded:   d.onboarded || false,
  };
}

// ── ROUTES ────────────────────────────────────────────────────────────────────

// POST /register
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name?.trim())            return res.status(400).json({ message: "Wpisz imię." });
    if (!email?.includes("@"))    return res.status(400).json({ message: "Niepoprawny email." });
    if (!password || password.length < 6) return res.status(400).json({ message: "Hasło min. 6 znaków." });

    const db  = loadDB();
    const key = email.trim().toLowerCase();
    if (db.users[key])            return res.status(409).json({ message: "Ten email jest już zajęty." });

    const hash         = await bcrypt.hash(password, 10);
    const verifyToken  = mailerEnabled ? crypto.randomBytes(32).toString("hex") : null;

    db.users[key] = {
      id:           crypto.randomUUID(),
      name:         name.trim(),
      email:        key,
      password:     hash,
      is_verified:  mailerEnabled ? false : true,
      is_premium:   false,
      verify_token: verifyToken,
      data:         {},
    };
    saveDB(db);

    if (mailerEnabled) {
      sendVerificationEmail(key, verifyToken).catch(e => console.error("Mail error:", e.message));
    }

    res.status(201).json({
      message: mailerEnabled
        ? "Sprawdź email — wysłaliśmy link aktywacyjny."
        : "Konto utworzone.",
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Błąd serwera." });
  }
});

// GET /verify?token=...
app.get("/verify", (req, res) => {
  const { token } = req.query;
  const db = loadDB();
  const user = Object.values(db.users).find(u => u.verify_token === token);
  if (!user) return res.status(400).send("Nieprawidłowy lub wygasły link.");
  db.users[user.email].is_verified  = true;
  db.users[user.email].verify_token = null;
  saveDB(db);
  res.redirect(`${process.env.FRONTEND_URL || "http://localhost:5173"}?verified=1`);
});

// POST /login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const db   = loadDB();
    const user = db.users[email?.trim().toLowerCase()];
    if (!user)                    return res.status(401).json({ message: "Nieprawidłowy email lub hasło." });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok)                      return res.status(401).json({ message: "Nieprawidłowy email lub hasło." });
    if (!user.is_verified)        return res.status(403).json({ message: "Potwierdź email — sprawdź skrzynkę." });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "90d" });
    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Błąd serwera." });
  }
});

// GET /me
app.get("/me", auth, (req, res) => {
  const db   = loadDB();
  const user = db.users[req.user.email];
  if (!user) return res.status(404).json({ message: "Użytkownik nie istnieje." });
  res.json(buildMe(user));
});

// POST /sync
app.post("/sync", auth, (req, res) => {
  const allowed = ["xp","streak","tasks","lessons","challenges","history","lastDay","onboarded"];
  const db      = loadDB();
  const user    = db.users[req.user.email];
  if (!user) return res.status(404).json({ message: "Użytkownik nie istnieje." });

  const current = user.data || {};
  for (const key of allowed) {
    if (req.body[key] !== undefined) current[key] = req.body[key];
  }
  db.users[req.user.email].data = current;
  saveDB(db);
  res.json({ ok: true });
});

// POST /activate-premium
app.post("/activate-premium", auth, (req, res) => {
  const code = (req.body.code || "").trim().toUpperCase();
  if (!PREMIUM_CODES.includes(code)) return res.status(400).json({ message: "Nieprawidłowy kod." });
  const db = loadDB();
  db.users[req.user.email].is_premium = true;
  saveDB(db);
  res.json({ ok: true, message: "Premium aktywowane!" });
});

// GET /leaderboard
app.get("/leaderboard", auth, (req, res) => {
  const db   = loadDB();
  const list = Object.values(db.users)
    .map(u => ({
      name:   u.name,
      email:  u.email,
      xp:     u.data?.xp     || 0,
      streak: u.data?.streak || 0,
      avatar: u.name.charAt(0).toUpperCase(),
    }))
    .sort((a, b) => b.xp - a.xp)
    .slice(0, 20);
  res.json(list);
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ Serwer działa na http://localhost:${PORT}`);
  console.log(`   Baza: ${DB_FILE}`);
  console.log(`   Email: ${mailerEnabled ? "włączony" : "wyłączony (konta aktywowane automatycznie)"}`);
  console.log(`   Kody premium: ${PREMIUM_CODES.join(", ")}\n`);
});
