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
app.use(cors());

const SB_URL = process.env.SUPABASE_URL;
const SB_KEY = process.env.SUPABASE_KEY;

const sbHeaders = {
  apikey: SB_KEY,
  Authorization: `Bearer ${SB_KEY}`,
  "Content-Type": "application/json",
  Prefer: "return=representation"
};

// ════ Supabase helper ════
async function sbFetch(path, opts = {}) {
  const res = await fetch(`${SB_URL}/rest/v1/${path}`, {
    ...opts,
    headers: { ...sbHeaders, ...(opts.headers || {}) }
  });
  const text = await res.text();
  try { return JSON.parse(text); } catch { return text; }
}

// ════ AUTH ════

// Регистрация
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
    return res.json({ success: false, error: "Ошибка создания аккаунта" });
  } catch (e) {
    console.error(e);
    return res.json({ success: false, error: "Ошибка сервера" });
  }
});

// Вход
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
    console.error(e);
    return res.json({ success: false, error: "Ошибка сервера" });
  }
});

// ════ FILES ════

// Категории с иконками
const CATEGORY_META = {
  math:        { label: "Математика",    icon: "∑",  color: "#7eb8ff" },
  physics:     { label: "Физика",        icon: "⚛",  color: "#b48dff" },
  chemistry:   { label: "Химия",         icon: "⚗",  color: "#4ecdc4" },
  history:     { label: "История",       icon: "📜",  color: "#ffb87a" },
  biology:     { label: "Биология",      icon: "🧬",  color: "#7de8a0" },
  literature:  { label: "Литература",    icon: "📖",  color: "#ff9ed2" },
  informatics: { label: "Информатика",   icon: "💻",  color: "#7eb8ff" },
  geography:   { label: "География",     icon: "🌍",  color: "#4ecdc4" },
};

// Получить список всех файлов
app.get("/api/files", (req, res) => {
  const filesRoot = path.join(__dirname, "files");
  const result = [];
  if (!fs.existsSync(filesRoot)) return res.json({ success: true, files: [] });
  const cats = fs.readdirSync(filesRoot, { withFileTypes: true })
    .filter(d => d.isDirectory()).map(d => d.name);
  cats.forEach(cat => {
    const catPath = path.join(filesRoot, cat);
    const files = fs.readdirSync(catPath).filter(f => !f.startsWith("."));
    files.forEach(file => {
      const stat = fs.statSync(path.join(catPath, file));
      const ext = path.extname(file).toLowerCase().slice(1);
      result.push({
        name: file,
        category: cat,
        categoryLabel: CATEGORY_META[cat]?.label || cat,
        categoryColor: CATEGORY_META[cat]?.color || "#888",
        categoryIcon: CATEGORY_META[cat]?.icon || "📁",
        ext,
        size: stat.size,
        modified: stat.mtime.toISOString(),
        url: `/files-static/${cat}/${encodeURIComponent(file)}`
      });
    });
  });
  return res.json({ success: true, files: result });
});

// Получить категории
app.get("/api/categories", (req, res) => {
  const filesRoot = path.join(__dirname, "files");
  const result = [];
  if (!fs.existsSync(filesRoot)) return res.json({ success: true, categories: [] });
  const cats = fs.readdirSync(filesRoot, { withFileTypes: true })
    .filter(d => d.isDirectory()).map(d => d.name);
  cats.forEach(cat => {
    const catPath = path.join(filesRoot, cat);
    const count = fs.readdirSync(catPath).filter(f => !f.startsWith(".")).length;
    result.push({
      slug: cat,
      label: CATEGORY_META[cat]?.label || cat,
      icon: CATEGORY_META[cat]?.icon || "📁",
      color: CATEGORY_META[cat]?.color || "#888",
      count
    });
  });
  return res.json({ success: true, categories: result });
});

// Отдаём статичные файлы из папки files/
app.use("/files-static", express.static(path.join(__dirname, "files")));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
