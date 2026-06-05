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

// POST /forgot-password
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const db  = loadDB();
    const key = email?.trim().toLowerCase();
    const user = db.users[key];

    // Zawsze odpowiadamy OK — żeby nie ujawniać czy email istnieje
    if (!user) return res.json({ message: "Jeśli konto istnieje, wysłaliśmy link na podany email." });

    const resetToken  = crypto.randomBytes(32).toString("hex");
    const resetExpiry = Date.now() + 60 * 60 * 1000; // 1 godzina

    db.users[key].reset_token  = resetToken;
    db.users[key].reset_expiry = resetExpiry;
    saveDB(db);

    if (transporter) {
      const url = `${process.env.FRONTEND_URL || "http://localhost:5173"}?reset=${resetToken}`;
      await transporter.sendMail({
        from: process.env.FROM_EMAIL || "Nawyki Wojownika <noreply@example.com>",
        to: key,
        subject: "Reset hasła — Nawyki Wojownika",
        html: `<div style="font-family:sans-serif;max-width:480px">
          <h2 style="color:#f0a500">⚔️ Nawyki Wojownika</h2>
          <p>Kliknij link żeby ustawić nowe hasło (ważny 1 godzinę):</p>
          <a href="${url}" style="display:inline-block;padding:12px 24px;background:#f0a500;color:#0f1923;font-weight:700;text-decoration:none;border-radius:8px">
            RESETUJ HASŁO →
          </a>
          <p style="color:#888;font-size:12px;margin-top:24px">Jeśli to nie Ty — zignoruj ten email.</p>
        </div>`,
      }).catch(e => console.error("Mail error:", e.message));
    } else {
      // Bez SMTP — zwróć token bezpośrednio (tylko dev)
      return res.json({ message: "Link resetujący (tryb dev):", devToken: resetToken });
    }

    res.json({ message: "Jeśli konto istnieje, wysłaliśmy link na podany email." });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Błąd serwera." });
  }
});

// POST /reset-password
app.post("/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!password || password.length < 6) return res.status(400).json({ message: "Hasło min. 6 znaków." });

    const db   = loadDB();
    const user = Object.values(db.users).find(u => u.reset_token === token);

    if (!user)                          return res.status(400).json({ message: "Link nieważny lub wygasły." });
    if (Date.now() > user.reset_expiry) return res.status(400).json({ message: "Link wygasł — wyślij nowy." });

    const hash = await bcrypt.hash(password, 10);
    db.users[user.email].password     = hash;
    db.users[user.email].reset_token  = null;
    db.users[user.email].reset_expiry = null;
    db.users[user.email].is_verified  = true; // aktywuj konto przy okazji
    saveDB(db);

    res.json({ message: "Hasło zostało zmienione. Możesz się zalogować." });
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

// POST /ai-chat — tylko premium
app.post("/ai-chat", auth, async (req, res) => {
  try {
    const db   = loadDB();
    const user = db.users[req.user.email];
    if (!user)            return res.status(404).json({ message: "Użytkownik nie istnieje." });
    if (!user.is_premium) return res.status(403).json({ message: "Ta funkcja dostępna jest tylko dla użytkowników premium." });

    const { messages, userData: ud } = req.body;
    if (!messages?.length) return res.status(400).json({ message: "Brak wiadomości." });

    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    if (!OPENAI_KEY) return res.status(500).json({ message: "Brak klucza OpenAI na serwerze." });

    // Buduj systemowy kontekst z danymi użytkownika
    const systemPrompt = `Jesteś Wojownik AI — osobisty asystent dyscypliny i nawyków w aplikacji "Nawyki Wojownika".
Rozmawiasz z użytkownikiem ${user.name}.

DANE UŻYTKOWNIKA:
- Streak: ${ud?.streak || 0} dni z rzędu
- XP: ${ud?.xp || 0} punktów
- Zadania dziś: ${(ud?.tasks || []).length}/${10} ukończonych
- Ukończone lekcje: ${(ud?.lessons || []).filter(l => typeof l === "number").length}/30
- Aktywne wyzwania: ${Object.values(ud?.challenges || {}).filter(c => c.active).length}

TWOJA ROLA:
- Motywuj, doradzaj i pomagaj budować dyscyplinę
- Odpowiadaj WYŁĄCZNIE po polsku
- Bądź konkretny — dawaj praktyczne wskazówki, nie ogólniki
- Nawiązuj do danych użytkownika gdy to możliwe
- Pisz krótko i na temat — max 3-4 zdania na odpowiedź
- Styl: wojowniczy, motywujący, bezpośredni — jak mentor nie terapeuta
- Nie używaj emoji w nadmiarze`;

    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${OPENAI_KEY}`,
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: systemPrompt },
          ...messages.slice(-10), // ostatnie 10 wiadomości (kontekst)
        ],
        max_tokens: 300,
        temperature: 0.8,
      }),
    });

    if (!response.ok) {
      const err = await response.json();
      console.error("OpenAI error:", err);
      return res.status(500).json({ message: "Błąd AI — spróbuj ponownie." });
    }

    const data = await response.json();
    const reply = data.choices[0].message.content;
    res.json({ reply });

  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Błąd serwera." });
  }
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ Serwer działa na http://localhost:${PORT}`);
  console.log(`   Baza: ${DB_FILE}`);
  console.log(`   Email: ${mailerEnabled ? "włączony" : "wyłączony (konta aktywowane automatycznie)"}`);
  console.log(`   Kody premium: ${PREMIUM_CODES.join(", ")}\n`);
});
