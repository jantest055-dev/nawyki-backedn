require("dotenv").config();
const express  = require("express");
const cors     = require("cors");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto   = require("crypto");
const mongoose = require("mongoose");

const app = express();
app.use(cors({
  origin: ["https://nawyki-wojownika-k2yh991if-puzon-s-projects.vercel.app", "https://nawyki-wojownika.vercel.app", "http://localhost:5173"],
  credentials: true,
}));
app.use(express.json());

// ── MONGODB ───────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB połączony"))
  .catch(e => { console.error("❌ MongoDB błąd:", e.message); process.exit(1); });

const userSchema = new mongoose.Schema({
  id:           { type: String, default: () => crypto.randomUUID() },
  name:         String,
  email:        { type: String, unique: true, lowercase: true, trim: true },
  password:     String,
  is_verified:  { type: Boolean, default: false },
  is_premium:   { type: Boolean, default: false },
  verify_token: String,
  reset_token:  String,
  reset_expiry: Number,
  data: {
    xp:         { type: Number, default: 0 },
    streak:     { type: Number, default: 1 },
    tasks:      { type: Array,  default: [] },
    lessons:    { type: Array,  default: [] },
    challenges: { type: Object, default: {} },
    history:    { type: Object, default: {} },
    lastDay:    { type: String, default: null },
    onboarded:  { type: Boolean, default: false },
  },
});

const User = mongoose.model("User", userSchema);

// ── CONFIG ────────────────────────────────────────────────────────────────────
const JWT_SECRET    = process.env.JWT_SECRET || "dev_secret_change_me";
const PORT          = process.env.PORT || 3000;
const PREMIUM_CODES = (process.env.PREMIUM_CODES || "WOJOWNIK2024,DYSCYPLINA77,NAWYKI2024,KOD77")
  .split(",").map(c => c.trim().toUpperCase());

// ── MAILER (Brevo API) ────────────────────────────────────────────────────────
const mailerEnabled = !!process.env.BREVO_API_KEY;

async function sendEmail(to, subject, html) {
  if (!mailerEnabled) return;
  const res = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "api-key": process.env.BREVO_API_KEY,
    },
    body: JSON.stringify({
      sender: { name: "Nawyki Wojownika", email: process.env.FROM_EMAIL || "ade1b5001@smtp-brevo.com" },
      to: [{ email: to }],
      subject,
      htmlContent: html,
    }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(JSON.stringify(err));
  }
}

async function sendVerificationEmail(email, token) {
  const url = `${process.env.FRONTEND_URL || "http://localhost:5173"}/verify?token=${token}`;
  const html = '<div style="font-family:sans-serif;max-width:480px;background:#0f1923;color:#fff;padding:32px;border-radius:12px">'
    + '<h2 style="color:#f0a500">Nawyki Wojownika</h2>'
    + '<p>Kliknij przycisk zeby aktywowac konto:</p>'
    + '<a href="' + url + '" style="display:inline-block;padding:14px 28px;background:#f0a500;color:#0f1923;text-decoration:none;border-radius:8px;font-weight:700;font-size:16px;margin:16px 0">AKTYWUJ KONTO</a>'
    + '<p style="color:#888;font-size:12px;margin-top:24px">Jesli to nie Ty - zignoruj ten email.</p>'
    + '</div>';
  await sendEmail(email, "Aktywuj konto - Nawyki Wojownika", html);
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
    if (!name?.trim())                   return res.status(400).json({ message: "Wpisz imię." });
    if (!email?.includes("@"))           return res.status(400).json({ message: "Niepoprawny email." });
    if (!password || password.length < 6) return res.status(400).json({ message: "Hasło min. 6 znaków." });

    const exists = await User.findOne({ email: email.trim().toLowerCase() });
    if (exists) return res.status(409).json({ message: "Ten email jest już zajęty." });

    const hash        = await bcrypt.hash(password, 10);
    const verifyToken = mailerEnabled ? crypto.randomBytes(32).toString("hex") : null;

    await User.create({
      name:         name.trim(),
      email:        email.trim().toLowerCase(),
      password:     hash,
      is_verified:  mailerEnabled ? false : true,
      verify_token: verifyToken,
    });

    if (mailerEnabled) {
      sendVerificationEmail(email.trim().toLowerCase(), verifyToken)
        .catch(e => console.error("Mail error:", e.message));
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
app.get("/verify", async (req, res) => {
  try {
    const { token } = req.query;
    const user = await User.findOne({ verify_token: token });
    if (!user) return res.status(400).send("Nieprawidłowy lub wygasły link.");
    user.is_verified  = true;
    user.verify_token = null;
    await user.save();
    res.redirect(`${process.env.FRONTEND_URL || "http://localhost:5173"}?verified=1`);
  } catch (e) {
    console.error(e);
    res.status(500).send("Błąd serwera.");
  }
});

// POST /login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email?.trim().toLowerCase() });
    if (!user) return res.status(401).json({ message: "Nieprawidłowy email lub hasło." });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok)   return res.status(401).json({ message: "Nieprawidłowy email lub hasło." });
    if (!user.is_verified) return res.status(403).json({ message: "Potwierdź email — sprawdź skrzynkę." });

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
    const key  = req.body.email?.trim().toLowerCase();
    const user = await User.findOne({ email: key });
    if (!user) return res.json({ message: "Jeśli konto istnieje, wysłaliśmy link na podany email." });

    const resetToken  = crypto.randomBytes(32).toString("hex");
    user.reset_token  = resetToken;
    user.reset_expiry = Date.now() + 60 * 60 * 1000;
    await user.save();

    if (mailerEnabled) {
      const url = `${process.env.FRONTEND_URL || "http://localhost:5173"}?reset=${resetToken}`;
      const html = '<div style="font-family:sans-serif;max-width:480px;background:#0f1923;color:#fff;padding:32px;border-radius:12px">'
        + '<h2 style="color:#f0a500">Nawyki Wojownika</h2>'
        + '<p>Kliknij link zeby ustawic nowe haslo (wazny 1 godzine):</p>'
        + '<a href="' + url + '" style="display:inline-block;padding:14px 28px;background:#f0a500;color:#0f1923;font-weight:700;text-decoration:none;border-radius:8px;font-size:16px;margin:16px 0">RESETUJ HASLO</a>'
        + '<p style="color:#888;font-size:12px;margin-top:24px">Jesli to nie Ty - zignoruj ten email.</p>'
        + '</div>';
      await sendEmail(key, "Reset hasla - Nawyki Wojownika", html).catch(e => console.error("Mail error:", e.message));
    } else {
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

    const user = await User.findOne({ reset_token: token });
    if (!user)                          return res.status(400).json({ message: "Link nieważny lub wygasły." });
    if (Date.now() > user.reset_expiry) return res.status(400).json({ message: "Link wygasł — wyślij nowy." });

    user.password     = await bcrypt.hash(password, 10);
    user.reset_token  = null;
    user.reset_expiry = null;
    user.is_verified  = true;
    await user.save();

    res.json({ message: "Hasło zostało zmienione. Możesz się zalogować." });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Błąd serwera." });
  }
});

// GET /me
app.get("/me", auth, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ message: "Użytkownik nie istnieje." });
    res.json(buildMe(user));
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Błąd serwera." });
  }
});

// POST /sync
app.post("/sync", auth, async (req, res) => {
  try {
    const allowed = ["xp","streak","tasks","lessons","challenges","history","lastDay","onboarded"];
    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ message: "Użytkownik nie istnieje." });

    for (const key of allowed) {
      if (req.body[key] !== undefined) user.data[key] = req.body[key];
    }
    user.markModified("data");
    await user.save();
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Błąd serwera." });
  }
});

// POST /activate-premium
app.post("/activate-premium", auth, async (req, res) => {
  try {
    const code = (req.body.code || "").trim().toUpperCase();
    if (!PREMIUM_CODES.includes(code)) return res.status(400).json({ message: "Nieprawidłowy kod." });
    const user = await User.findOne({ email: req.user.email });
    user.is_premium = true;
    await user.save();
    res.json({ ok: true, message: "Premium aktywowane!" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Błąd serwera." });
  }
});

// GET /leaderboard
app.get("/leaderboard", auth, async (req, res) => {
  try {
    const users = await User.find({}, "name email data").lean();
    const list = users
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
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Błąd serwera." });
  }
});

// POST /ai-chat — tylko premium
app.post("/ai-chat", auth, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    if (!user)            return res.status(404).json({ message: "Użytkownik nie istnieje." });
    if (!user.is_premium) return res.status(403).json({ message: "Ta funkcja dostępna jest tylko dla użytkowników premium." });

    const { messages, userData: ud } = req.body;
    if (!messages?.length) return res.status(400).json({ message: "Brak wiadomości." });

    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    if (!OPENAI_KEY) return res.status(500).json({ message: "Brak klucza OpenAI na serwerze." });

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
          ...messages.slice(-10),
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

    const data  = await response.json();
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
  console.log(`   Email: ${mailerEnabled ? "włączony" : "wyłączony"}`);
  console.log(`   Kody premium: ${PREMIUM_CODES.join(", ")}\n`);
});
