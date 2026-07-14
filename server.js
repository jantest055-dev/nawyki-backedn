require("dotenv").config();
const express  = require("express");
const cors     = require("cors");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const crypto   = require("crypto");
const mongoose = require("mongoose");
const Stripe   = require("stripe");
const webpush  = require("web-push");

const stripe = process.env.STRIPE_SECRET_KEY ? Stripe(process.env.STRIPE_SECRET_KEY) : null;

if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(
    `mailto:${process.env.FROM_EMAIL || "kontakt@nawykiwojownika.pl"}`,
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );
}

const PLANS = {
  monthly: { name: "Premium 1 miesiąc", price: 4700, interval: "month", months: 1 },
  quarterly: { name: "Premium 3 miesiące", price: 9700, interval: null, months: 3 },
  yearly: { name: "Premium 1 rok", price: 34900, interval: "year", months: 12 },
};

const app = express();

// Stripe webhook musi mieć raw body — przed express.json()
app.post("/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  if (!stripe) return res.status(500).json({ message: "Stripe nie skonfigurowany." });
  const sig = req.headers["stripe-signature"];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    console.error("Webhook błąd:", e.message);
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const email   = session.customer_email || session.metadata?.email;
    const months  = parseInt(session.metadata?.months || "1");
    if (email) {
      try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (user) {
          user.is_premium = true;
          const now = new Date();
          const expiry = new Date(now);
          expiry.setMonth(expiry.getMonth() + months);
          user.premium_expiry = expiry;
          await user.save();
          console.log(`✅ Premium aktywowane dla ${email} do ${expiry.toISOString()}`);
        }
      } catch (e) {
        console.error("Błąd aktywacji premium:", e.message);
      }
    }
  }
  res.json({ received: true });
});

app.use(cors({
  origin: ["https://nawyki-wojownika-k2yh991if-puzon-s-projects.vercel.app", "https://nawyki-wojownika.vercel.app", "https://nawyki-frontend.vercel.app", "https://dyscyplinawojownika.pl", "https://www.dyscyplinawojownika.pl", "http://localhost:5173"],
  credentials: true,
}));
app.use(express.json());

// ── MONGODB ───────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB połączony"))
  .catch(e => { console.error("❌ MongoDB błąd:", e.message); process.exit(1); });

const userSchema = new mongoose.Schema({
  id:              { type: String, default: () => crypto.randomUUID() },
  name:            String,
  email:           { type: String, unique: true, lowercase: true, trim: true },
  password:        String,
  is_verified:     { type: Boolean, default: false },
  is_premium:      { type: Boolean, default: false },
  premium_expiry:  { type: Date, default: null },
  verify_token:    String,
  reset_token:     String,
  reset_expiry:    Number,
  push_subscription: { type: Object, default: null },
  data: {
    xp:         { type: Number, default: 0 },
    streak:     { type: Number, default: 1 },
    tasks:      { type: Array,  default: [] },
    lessons:    { type: Array,  default: [] },
    challenges: { type: Object, default: {} },
    history:    { type: Object, default: {} },
    lastDay:    { type: String, default: null },
    onboarded:  { type: Boolean, default: false },
    goals:      { type: Array,  default: [] },
  },
});

const User = mongoose.model("User", userSchema);

// ── CONFIG ────────────────────────────────────────────────────────────────────
const JWT_SECRET    = process.env.JWT_SECRET || "dev_secret_change_me";
const PORT          = process.env.PORT || 3000;
const PREMIUM_CODES = (process.env.PREMIUM_CODES || "WOJOWNIK2024,DYSCYPLINA77,NAWYKI2024,KOD77")
  .split(",").map(c => c.trim().toUpperCase());

// ── MAILER (Brevo API) ────────────────────────────────────────────────────────
const mailerEnabled = !!process.env.RESEND_API_KEY;

async function sendEmail(to, subject, html) {
  if (!mailerEnabled) return;
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + process.env.RESEND_API_KEY,
    },
    body: JSON.stringify({
      from: process.env.FROM_EMAIL || "Nawyki Wojownika <onboarding@resend.dev>",
      to: [to],
      subject,
      html,
    }),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(JSON.stringify(err));
  }
}

async function sendVerificationEmail(email, token) {
  const backendUrl = process.env.BACKEND_URL || "https://nawyki-backedn.onrender.com";
  const url = `${backendUrl}/verify?token=${token}`;
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
  const premiumActive = !!user.is_premium && (!user.premium_expiry || new Date(user.premium_expiry) > new Date());
  return {
    id:             user.id,
    name:           user.name,
    email:          user.email,
    is_premium:     premiumActive,
    premium_expiry: user.premium_expiry || null,
    is_verified:    !!user.is_verified,
    xp:             d.xp        || 0,
    streak:         d.streak    || 1,
    tasks:          d.tasks     || [],
    lessons:        d.lessons   || [],
    challenges:     d.challenges|| {},
    history:        d.history   || {},
    lastDay:        d.lastDay   || null,
    onboarded:      d.onboarded || false,
    goals:          d.goals     || [],
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
    const allowed = ["xp","streak","tasks","lessons","challenges","history","lastDay","onboarded","goals"];
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

// POST /generate-goal — generuje plan celu na 30 dni
app.post("/generate-goal", auth, async (req, res) => {
  try {
    const { goal } = req.body;
    if (!goal?.trim()) return res.status(400).json({ message: "Wpisz cel." });

    const OPENAI_KEY = process.env.OPENAI_API_KEY;
    if (!OPENAI_KEY) return res.status(500).json({ message: "Brak klucza OpenAI na serwerze." });

    const prompt = `Użytkownik chce osiągnąć cel: "${goal}"

Rozpisz plan na 30 dni. Podziel go na 5 etapów po 6 dni każdy.
Dla każdego etapu podaj 3 konkretne codzienne zadania (nawyki).

Odpowiedz TYLKO w formacie JSON, bez żadnego tekstu przed ani po:
{
  "goal": "nazwa celu",
  "summary": "krótki opis planu (1 zdanie)",
  "stages": [
    {
      "stage": 1,
      "days": "1-6",
      "name": "nazwa etapu",
      "tasks": ["zadanie 1", "zadanie 2", "zadanie 3"]
    }
  ]
}`;

    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + OPENAI_KEY,
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: prompt }],
        max_tokens: 1000,
        temperature: 0.7,
      }),
    });

    if (!response.ok) {
      const err = await response.json();
      console.error("OpenAI error:", err);
      return res.status(500).json({ message: "Blad AI — sprobuj ponownie." });
    }

    const data = await response.json();
    const text = data.choices[0].message.content;

    let plan;
    try {
      plan = JSON.parse(text);
    } catch {
      return res.status(500).json({ message: "AI zwrocilo niepoprawny format — sprobuj ponownie." });
    }

    // Zapisz plan w danych uzytkownika
    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ message: "Uzytkownik nie istnieje." });

    if (!user.data.goals) user.data.goals = [];
    user.data.goals.push({
      id:        crypto.randomUUID(),
      createdAt: new Date().toISOString(),
      plan,
    });
    user.markModified("data");
    await user.save();

    res.json({ ok: true, plan });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Blad serwera." });
  }
});

// GET /plans
app.get("/plans", (req, res) => {
  res.json([
    { id: "monthly",   name: "Premium 1 miesiąc",   price: 47,  currency: "PLN", months: 1 },
    { id: "quarterly", name: "Premium 3 miesiące",  price: 97,  currency: "PLN", months: 3 },
    { id: "yearly",    name: "Premium 1 rok",        price: 349, currency: "PLN", months: 12 },
  ]);
});

// POST /create-checkout-session
app.post("/create-checkout-session", auth, async (req, res) => {
  try {
    if (!stripe) return res.status(500).json({ message: "Płatności nie są skonfigurowane." });
    const { planId } = req.body;
    const plan = PLANS[planId];
    if (!plan) return res.status(400).json({ message: "Nieprawidłowy plan." });

    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ message: "Użytkownik nie istnieje." });

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card", "p24"],
      customer_email: user.email,
      line_items: [{
        price_data: {
          currency: "pln",
          product_data: { name: plan.name },
          unit_amount: plan.price,
        },
        quantity: 1,
      }],
      mode: "payment",
      metadata: { email: user.email, months: String(plan.months) },
      success_url: `${process.env.FRONTEND_URL || "http://localhost:5173"}/premium?success=1`,
      cancel_url:  `${process.env.FRONTEND_URL || "http://localhost:5173"}/premium?canceled=1`,
    });

    res.json({ url: session.url });
  } catch (e) {
    console.error("Stripe error:", e.message);
    res.status(500).json({ message: "Błąd płatności." });
  }
});

// GET /stats
app.get("/stats", auth, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ message: "Użytkownik nie istnieje." });

    const d = user.data || {};
    const history = d.history || {};
    const days = Object.keys(history).sort();

    const totalDays   = days.length;
    const totalXP     = d.xp || 0;
    const totalTasks  = days.reduce((s, k) => s + (history[k].tasksDone || 0), 0);
    const bestStreak  = (() => {
      let best = 0, cur = 0, prev = null;
      for (const day of days) {
        if (prev) {
          const diff = (new Date(day) - new Date(prev)) / 86400000;
          cur = diff === 1 ? cur + 1 : 1;
        } else { cur = 1; }
        if (cur > best) best = cur;
        prev = day;
      }
      return best;
    })();

    const xpHistory = days.slice(-30).map(day => ({ day, xp: history[day]?.xp || 0 }));

    res.json({
      totalDays,
      totalXP,
      totalTasks,
      currentStreak: d.streak || 0,
      bestStreak,
      lessonsCompleted: (d.lessons || []).length,
      goalsCreated: (d.goals || []).length,
      xpHistory,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Błąd serwera." });
  }
});

// POST /push/subscribe
app.post("/push/subscribe", auth, async (req, res) => {
  try {
    const { subscription } = req.body;
    if (!subscription) return res.status(400).json({ message: "Brak subskrypcji." });

    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ message: "Użytkownik nie istnieje." });

    user.push_subscription = subscription;
    await user.save();
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Błąd serwera." });
  }
});

// POST /push/send — wysyła powiadomienie do zalogowanego użytkownika
app.post("/push/send", auth, async (req, res) => {
  try {
    if (!process.env.VAPID_PUBLIC_KEY) return res.status(500).json({ message: "Push nie skonfigurowany." });
    const { title, body } = req.body;
    const user = await User.findOne({ email: req.user.email });
    if (!user?.push_subscription) return res.status(404).json({ message: "Brak subskrypcji push." });

    await webpush.sendNotification(user.push_subscription, JSON.stringify({ title, body }));
    res.json({ ok: true });
  } catch (e) {
    console.error("Push error:", e.message);
    res.status(500).json({ message: "Błąd push." });
  }
});

// GET /vapid-public-key — frontend potrzebuje klucza do subskrypcji
app.get("/vapid-public-key", (req, res) => {
  const key = process.env.VAPID_PUBLIC_KEY;
  if (!key) return res.status(404).json({ message: "Push nie skonfigurowany." });
  res.json({ key });
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ Serwer działa na http://localhost:${PORT}`);
  console.log(`   Email: ${mailerEnabled ? "włączony" : "wyłączony"}`);
  console.log(`   Kody premium: ${PREMIUM_CODES.join(", ")}\n`);
});
