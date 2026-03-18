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
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.static("public"));
app.use(cors({ origin: true, credentials: true }));

const SB_URL = process.env.SUPABASE_URL;
const SB_KEY = process.env.SUPABASE_KEY;

if (!SB_URL || !SB_KEY) {
  console.error("⚠️  SUPABASE_URL или SUPABASE_KEY не заданы!");
}

const sbHeaders = {
  apikey: SB_KEY,
  Authorization: `Bearer ${SB_KEY}`,
  "Content-Type": "application/json",
  Prefer: "return=representation"
};

async function sbFetch(endpoint, opts = {}) {
  if (!SB_URL || !SB_KEY)
    throw new Error("Supabase не настроен — добавь SUPABASE_URL и SUPABASE_KEY");
  const res = await fetch(`${SB_URL}/rest/v1/${endpoint}`, {
    ...opts,
    headers: { ...sbHeaders, ...(opts.headers || {}) }
  });
  const text = await res.text();
  if (!res.ok) {
    console.error(`Supabase [${res.status}]:`, text.slice(0, 300));
    throw new Error(`Supabase ${res.status}: ${text.slice(0, 200)}`);
  }
  try { return JSON.parse(text); } catch { return text; }
}

// ════ AUTH ════

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
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
    console.error("register:", e.message);
    return res.json({ success: false, error: e.message });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
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
    console.error("login:", e.message);
    return res.json({ success: false, error: e.message });
  }
});

// ════ FILES ════
// Файлы лежат в public/files/(категория)/файл — деплоятся как статика Vercel
// Список файлов — public/files-index.json (генерируется через: node generate-index.js)

const CATEGORY_META = {
  math:        { label: "Математика",    icon: "∑",   color: "#7eb8ff" },
  physics:     { label: "Физика",        icon: "⚛",   color: "#b48dff" },
  chemistry:   { label: "Химия",         icon: "⚗",   color: "#4ecdc4" },
  history:     { label: "История",       icon: "📜",  color: "#ffb87a" },
  biology:     { label: "Биология",      icon: "🧬",  color: "#7de8a0" },
  literature:  { label: "Литература",    icon: "📖",  color: "#ff9ed2" },
  informatics: { label: "Информатика",   icon: "💻",  color: "#7eb8ff" },
  geography:   { label: "География",     icon: "🌍",  color: "#4ecdc4" },
};

function loadFilesIndex() {
  // Сначала public/files-index.json (работает на Vercel)
  const indexPath = path.join(process.cwd(), "public", "files-index.json");
  if (fs.existsSync(indexPath)) {
    try { return JSON.parse(fs.readFileSync(indexPath, "utf8")); }
    catch (e) { console.error("files-index.json:", e.message); }
  }
  // Fallback: сканируем public/files/ (только локально)
  const filesRoot = path.join(process.cwd(), "public", "files");
  if (!fs.existsSync(filesRoot)) return [];
  const result = [];
  try {
    fs.readdirSync(filesRoot, { withFileTypes: true })
      .filter(d => d.isDirectory()).forEach(({ name: cat }) => {
        const catPath = path.join(filesRoot, cat);
        fs.readdirSync(catPath).filter(f => !f.startsWith(".")).forEach(file => {
          try {
            const stat = fs.statSync(path.join(catPath, file));
            const ext = path.extname(file).toLowerCase().slice(1);
            result.push({
              name: file, category: cat,
              categoryLabel: CATEGORY_META[cat]?.label || cat,
              categoryColor: CATEGORY_META[cat]?.color || "#888",
              categoryIcon: CATEGORY_META[cat]?.icon || "📁",
              ext, size: stat.size,
              modified: stat.mtime.toISOString(),
              url: `/files/${cat}/${encodeURIComponent(file)}`
            });
          } catch {}
        });
      });
  } catch {}
  return result;
}

app.get("/api/files", (req, res) => {
  res.json({ success: true, files: loadFilesIndex() });
});

app.get("/api/categories", (req, res) => {
  const map = {};
  loadFilesIndex().forEach(f => {
    if (!map[f.category]) map[f.category] = { slug: f.category, label: f.categoryLabel, icon: f.categoryIcon, color: f.categoryColor, count: 0 };
    map[f.category].count++;
  });
  res.json({ success: true, categories: Object.values(map) });
});

app.get("/api/health", (req, res) => {
  const indexPath = path.join(process.cwd(), "public", "files-index.json");
  res.json({
    ok: true,
    supabase_url: SB_URL ? SB_URL.slice(0, 35) + "..." : "NOT SET ❌",
    supabase_key: SB_KEY ? "✓ задан" : "NOT SET ❌",
    files_index_exists: fs.existsSync(indexPath),
    cwd: process.cwd(),
    node: process.version,
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ http://localhost:${PORT}`));
