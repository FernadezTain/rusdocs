import express from "express";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import cors from "cors";
import fetch from "node-fetch";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(cors({ origin: true, credentials: true }));

const SB_URL = process.env.SUPABASE_URL;
const SB_KEY = process.env.SUPABASE_KEY;

const sbHeaders = () => ({
  apikey: SB_KEY,
  Authorization: `Bearer ${SB_KEY}`,
  "Content-Type": "application/json",
  Prefer: "return=representation"
});

async function sbFetch(endpoint, opts = {}) {
  if (!SB_URL || !SB_KEY)
    throw new Error("SUPABASE_URL / SUPABASE_KEY не заданы в переменных окружения Vercel");
  const res = await fetch(`${SB_URL}/rest/v1/${endpoint}`, {
    ...opts,
    headers: { ...sbHeaders(), ...(opts.headers || {}) }
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase ${res.status}: ${text.slice(0, 200)}`);
  try { return JSON.parse(text); } catch { return text; }
}

// ════ REGISTER ════
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.json({ success: false, error: "Заполни все поля" });
  if (username.length < 3)
    return res.json({ success: false, error: "Логин минимум 3 символа" });
  if (password.length < 4)
    return res.json({ success: false, error: "Пароль минимум 4 символа" });
  try {
    const check = await sbFetch(`users?username=eq.${encodeURIComponent(username)}&select=id`);
    if (Array.isArray(check) && check.length)
      return res.json({ success: false, error: "Пользователь уже существует" });
    const hash = await bcrypt.hash(password, 10);
    const created = await sbFetch("users", {
      method: "POST",
      body: JSON.stringify({ username, password_hash: hash, role: "user" })
    });
    if (Array.isArray(created) && created[0])
      return res.json({ success: true, user: { id: created[0].id, username: created[0].username, role: created[0].role } });
    return res.json({ success: false, error: "Ошибка создания" });
  } catch (e) {
    return res.json({ success: false, error: e.message });
  }
});

// ════ LOGIN ════
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.json({ success: false, error: "Заполни все поля" });
  try {
    const rows = await sbFetch(`users?username=eq.${encodeURIComponent(username)}&select=*`);
    if (!Array.isArray(rows) || !rows.length)
      return res.json({ success: false, error: "Пользователь не найден" });
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match)
      return res.json({ success: false, error: "Неверный пароль" });
    return res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
  } catch (e) {
    return res.json({ success: false, error: e.message });
  }
});

// ════ FILES ════
const CATEGORY_META = {
  math:        { label: "Математика",  icon: "∑",  color: "#7eb8ff" },
  physics:     { label: "Физика",      icon: "⚛",  color: "#b48dff" },
  chemistry:   { label: "Химия",       icon: "⚗",  color: "#4ecdc4" },
  history:     { label: "История",     icon: "📜", color: "#ffb87a" },
  biology:     { label: "Биология",    icon: "🧬", color: "#7de8a0" },
  literature:  { label: "Литература",  icon: "📖", color: "#ff9ed2" },
  informatics: { label: "Информатика", icon: "💻", color: "#7eb8ff" },
  geography:   { label: "География",   icon: "🌍", color: "#4ecdc4" },
};

function loadIndex() {
  const p = path.join(__dirname, "public", "files-index.json");
  if (fs.existsSync(p)) {
    try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch {}
  }
  return [];
}

app.get("/api/files", (_req, res) => {
  res.json({ success: true, files: loadIndex() });
});

app.get("/api/categories", (_req, res) => {
  const map = {};
  loadIndex().forEach(f => {
    if (!map[f.category])
      map[f.category] = { slug: f.category, label: f.categoryLabel, icon: f.categoryIcon, color: f.categoryColor, count: 0 };
    map[f.category].count++;
  });
  res.json({ success: true, categories: Object.values(map) });
});

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    supabase_url: SB_URL ? SB_URL.slice(8, 35) + "..." : "NOT SET ❌",
    supabase_key: SB_KEY ? "✓" : "NOT SET ❌",
    index: fs.existsSync(path.join(__dirname, "public", "files-index.json")),
  });
});

// ════ Vercel: экспортируем app, НЕ вызываем listen ════
// Локально — слушаем порт
if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`http://localhost:${PORT}`));
}

export default app;
