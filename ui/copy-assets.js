// Copies the self-hosted Inter font files and the Lucide icons the app uses into app/static.
const fs = require("fs");
const path = require("path");

const STATIC = path.join(__dirname, "..", "app", "static");
const fonts = path.join(STATIC, "fonts");
const icons = path.join(STATIC, "icons");
fs.mkdirSync(fonts, { recursive: true });
fs.mkdirSync(icons, { recursive: true });

const fontDir = path.join(__dirname, "node_modules", "@fontsource", "inter", "files");
const wanted = [
  ...[400, 500, 600, 700].map((w) => `inter-latin-${w}-normal.woff2`),
  ...[400, 600].map((w) => `inter-latin-ext-${w}-normal.woff2`),
  ...[400, 500, 600, 700].map((w) => `inter-greek-${w}-normal.woff2`),
];
for (const f of wanted) fs.copyFileSync(path.join(fontDir, f), path.join(fonts, f));

// Every icon referenced by icon('...') in templates must be listed here (the app fails fast if one is missing).
const ICONS = [
  "calendar", "chevron-left", "chevron-right", "chevron-down", "layout-grid", "arrow-left-right", "plus", "scan-line",
  "ellipsis", "shapes", "repeat", "settings", "shield-check", "log-out", "arrow-down-left", "arrow-up-right",
  "triangle-alert", "wallet", "piggy-bank", "search", "sliders-horizontal", "pencil", "trash-2", "camera",
  "file-up", "check", "x", "copy", "download", "mail", "lock", "key-round", "circle-check", "circle-alert",
  "info", "loader-circle", "file-spreadsheet", "sun", "moon", "monitor", "user", "smartphone", "receipt",
  "landmark", "arrow-left", "house", "trending-up", "list", "sparkles", "eye-off",
];
const src = path.join(__dirname, "node_modules", "lucide-static", "icons");
for (const name of ICONS) fs.copyFileSync(path.join(src, `${name}.svg`), path.join(icons, `${name}.svg`));
console.log(`copied ${wanted.length} font files and ${ICONS.length} icons`);
