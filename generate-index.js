// Запускай после добавления новых файлов: node generate-index.js
// Генерирует public/files-index.json — список всех файлов для Vercel

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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

const filesRoot = path.join(__dirname, "public", "files");
const outPath   = path.join(__dirname, "public", "files-index.json");

if (!fs.existsSync(filesRoot)) {
  console.error("❌ Папка public/files/ не найдена");
  process.exit(1);
}

const result = [];
let total = 0;

fs.readdirSync(filesRoot, { withFileTypes: true })
  .filter(d => d.isDirectory())
  .forEach(({ name: cat }) => {
    const catPath = path.join(filesRoot, cat);
    fs.readdirSync(catPath)
      .filter(f => !f.startsWith("."))
      .forEach(file => {
        try {
          const stat = fs.statSync(path.join(catPath, file));
          const ext  = path.extname(file).toLowerCase().slice(1);
          result.push({
            name: file,
            category: cat,
            categoryLabel: CATEGORY_META[cat]?.label || cat,
            categoryColor: CATEGORY_META[cat]?.color || "#888",
            categoryIcon:  CATEGORY_META[cat]?.icon  || "📁",
            ext,
            size: stat.size,
            modified: stat.mtime.toISOString(),
            url: `/files/${cat}/${encodeURIComponent(file)}`
          });
          total++;
        } catch {}
      });
  });

fs.writeFileSync(outPath, JSON.stringify(result, null, 2), "utf8");
console.log(`✅ Готово! Записано ${total} файлов → public/files-index.json`);
