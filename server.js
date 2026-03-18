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
app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use(cors({ origin: true, credentials: true }));

const SB_URL     = process.env.SUPABASE_URL;
const SB_KEY     = process.env.SUPABASE_KEY;          // anon key — для REST API
const SB_SERVICE = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_KEY; // service_role — для Storage

const sbH = () => ({
  apikey: SB_KEY,
  Authorization: `Bearer ${SB_KEY}`,
  "Content-Type": "application/json",
  Prefer: "return=representation"
});

async function sb(endpoint, opts = {}) {
  if (!SB_URL || !SB_KEY) throw new Error("Supabase не настроен");
  const res = await fetch(`${SB_URL}/rest/v1/${endpoint}`, {
    ...opts, headers: { ...sbH(), ...(opts.headers || {}) }
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase ${res.status}: ${text.slice(0,200)}`);
  try { return JSON.parse(text); } catch { return text; }
}

// Middleware: проверка что юзер — админ (по userId в заголовке)
async function requireAdmin(req, res, next) {
  const userId = req.headers["x-user-id"];
  if (!userId) return res.status(403).json({ success: false, error: "Нет доступа" });
  try {
    const rows = await sb(`users?id=eq.${userId}&select=role`);
    if (!Array.isArray(rows) || !rows[0] || rows[0].role !== "admin")
      return res.status(403).json({ success: false, error: "Только для администраторов" });
    next();
  } catch (e) {
    return res.status(403).json({ success: false, error: e.message });
  }
}

// ════ AUTH ════
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.json({ success: false, error: "Заполни все поля" });
  if (username.length < 3)    return res.json({ success: false, error: "Логин минимум 3 символа" });
  if (password.length < 4)    return res.json({ success: false, error: "Пароль минимум 4 символа" });
  try {
    const check = await sb(`users?username=eq.${encodeURIComponent(username)}&select=id`);
    if (Array.isArray(check) && check.length)
      return res.json({ success: false, error: "Пользователь уже существует" });
    const hash = await bcrypt.hash(password, 10);
    const created = await sb("users", {
      method: "POST",
      body: JSON.stringify({ username, password_hash: hash, role: "user" })
    });
    if (Array.isArray(created) && created[0])
      return res.json({ success: true, user: { id: created[0].id, username: created[0].username, role: created[0].role } });
    return res.json({ success: false, error: "Ошибка создания" });
  } catch (e) { return res.json({ success: false, error: e.message }); }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.json({ success: false, error: "Заполни все поля" });
  try {
    const rows = await sb(`users?username=eq.${encodeURIComponent(username)}&select=*`);
    if (!Array.isArray(rows) || !rows.length)
      return res.json({ success: false, error: "Пользователь не найден" });
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.json({ success: false, error: "Неверный пароль" });
    return res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
  } catch (e) { return res.json({ success: false, error: e.message }); }
});

// ════ ADMIN: USERS ════
app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const q = req.query.q ? `&username=ilike.*${req.query.q}*` : "";
    const rows = await sb(`users?select=id,username,role,created_at&order=created_at.desc${q}`);
    res.json({ success: true, users: rows });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.patch("/api/admin/users/:id", requireAdmin, async (req, res) => {
  const { username, password, role } = req.body || {};
  const update = {};
  if (username) update.username = username;
  if (role)     update.role = role;
  if (password) update.password_hash = await bcrypt.hash(password, 10);
  try {
    const rows = await sb(`users?id=eq.${req.params.id}`, {
      method: "PATCH", body: JSON.stringify(update)
    });
    res.json({ success: true, user: rows[0] });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ════ ADMIN: SECTIONS ════
app.get("/api/sections", async (req, res) => {
  try {
    let q = "?order=created_at.desc";
    if (req.query.category) q += `&category=eq.${req.query.category}`;
    // parent_id: null = корневые, uuid = дочерние
    if (req.query.parent_id === "null") q += "&parent_id=is.null";
    else if (req.query.parent_id)       q += `&parent_id=eq.${req.query.parent_id}`;
    const rows = await sb(`sections${q}&select=*`);
    res.json({ success: true, sections: rows });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post("/api/sections", requireAdmin, async (req, res) => {
  const { category, title, parent_id } = req.body || {};
  if (!category || !title) return res.json({ success: false, error: "Нет данных" });
  try {
    const userId = req.headers["x-user-id"];
    const payload = { category, title, created_by: userId, is_folder: !!req.body.is_folder };
    if (parent_id) payload.parent_id = parent_id;
    const rows = await sb("sections", { method: "POST", body: JSON.stringify(payload) });
    res.json({ success: true, section: rows[0] });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.delete("/api/sections/:id", requireAdmin, async (req, res) => {
  try {
    await sb(`sections?id=eq.${req.params.id}`, { method: "DELETE" });
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ════ ADMIN: FILES ════
app.get("/api/files-db", async (req, res) => {
  try {
    const q = req.query.section_id ? `?section_id=eq.${req.query.section_id}&order=created_at.asc` : "?order=created_at.desc";
    const rows = await sb(`files${q}&select=*`);
    res.json({ success: true, files: rows });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Загрузка файла (base64)
app.post("/api/files-db", requireAdmin, async (req, res) => {
  const { section_id, name, original_name, size, ext, data } = req.body || {};
  if (!section_id || !original_name || !data)
    return res.json({ success: false, error: "Нет данных" });

  try {
    const userId = req.headers["x-user-id"];

    // Загружаем в Supabase Storage через API
    const storageKey = `${section_id}/${Date.now()}_${original_name}`;
    const buf = Buffer.from(data, "base64");

    // Storage требует service_role key (не anon)
    const upRes = await fetch(
      `${SB_URL}/storage/v1/object/RusDocs/${storageKey}`,
      {
        method: "POST",
        headers: {
          apikey: SB_SERVICE,
          Authorization: `Bearer ${SB_SERVICE}`,
          "Content-Type": "application/octet-stream",
          "x-upsert": "true"
        },
        body: buf
      }
    );

    let url;
    if (upRes.ok) {
      url = `${SB_URL}/storage/v1/object/public/RusDocs/${storageKey}`;
    } else {
      const errText = await upRes.text();
      console.error("Storage upload failed:", upRes.status, errText.slice(0, 200));
      return res.json({ success: false, error: `Storage error ${upRes.status}: ${errText.slice(0,120)}` });
    }

    const rows = await sb("files", {
      method: "POST",
      body: JSON.stringify({ section_id, name: name || original_name, original_name, size, ext, url, created_by: userId })
    });
    res.json({ success: true, file: rows[0] });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.delete("/api/files-db/:id", requireAdmin, async (req, res) => {
  try {
    await sb(`files?id=eq.${req.params.id}`, { method: "DELETE" });
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ════ PUBLIC FILES (старый json-индекс, для совместимости) ════
const CATEGORY_META = {
  russian:     { label: "Русский язык",        icon: "Я", color: "#e8c96a" },
  literature:  { label: "Литература",           icon: "📖", color: "#ff9ed2" },
  folklore:    { label: "Фольклор",             icon: "🎭", color: "#b48dff" },
  classical:   { label: "Классика XIX века",    icon: "🪶", color: "#7eb8ff" },
  modern:      { label: "Литература XX–XXI в.", icon: "✍️", color: "#4ecdc4" },
  foreign:     { label: "Зарубежная лит-ра",   icon: "🌍", color: "#7de8a0" },
  theory:      { label: "Теория литературы",    icon: "📐", color: "#ffb87a" },
  essays:      { label: "Сочинения и эссе",     icon: "📝", color: "#ff9ed2" },
};

app.get("/api/files", async (_req, res) => {
  // Отдаём файлы из БД
  try {
    const sections = await sb("sections?select=id,category,title");
    const files    = await sb("files?select=*");
    const result = (files || []).map(f => {
      const sec = (sections || []).find(s => s.id === f.section_id);
      const cat = sec?.category || "other";
      const meta = CATEGORY_META[cat] || { label: cat, icon: "📁", color: "#888" };
      return {
        id: f.id, name: f.original_name,
        category: cat, categoryLabel: meta.label, categoryColor: meta.color, categoryIcon: meta.icon,
        section: sec?.title || "",
        ext: f.ext, size: f.size,
        modified: f.created_at,
        url: f.url
      };
    });
    res.json({ success: true, files: result });
  } catch (e) {
    // Fallback на json-индекс
    const p = path.join(__dirname, "public", "files-index.json");
    if (fs.existsSync(p)) {
      try { return res.json({ success: true, files: JSON.parse(fs.readFileSync(p, "utf8")) }); } catch {}
    }
    res.json({ success: true, files: [] });
  }
});

app.get("/api/categories", async (_req, res) => {
  try {
    const sections = await sb("sections?select=category");
    const map = {};
    (sections || []).forEach(s => {
      const meta = CATEGORY_META[s.category];
      if (meta && !map[s.category])
        map[s.category] = { slug: s.category, ...meta, count: 0 };
      if (map[s.category]) map[s.category].count++;
    });
    // Если разделов нет, возвращаем все категории
    if (!Object.keys(map).length) {
      return res.json({ success: true, categories: Object.entries(CATEGORY_META).map(([slug, m]) => ({ slug, ...m, count: 0 })) });
    }
    res.json({ success: true, categories: Object.values(map) });
  } catch (e) { res.json({ success: true, categories: [] }); }
});

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    supabase_url: SB_URL ? SB_URL.slice(8, 35) + "..." : "NOT SET ❌",
    supabase_key: SB_KEY ? "✓" : "NOT SET ❌",
  });
});

if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`http://localhost:${PORT}`));
}

export default app;
