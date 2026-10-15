// Builds every Oikonomy logo asset from ui/brand/mark.svg -> app/static/brand (run: npm run icons).
const fs = require("fs");
const path = require("path");
const { Resvg } = require("@resvg/resvg-js");

const BLUE = "#2563EB";
const OUT = path.join(__dirname, "..", "app", "static", "brand");
fs.mkdirSync(OUT, { recursive: true });

const mark = fs.readFileSync(path.join(__dirname, "brand", "mark.svg"), "utf8");
const inner = mark.replace(/^[\s\S]*?<svg[^>]*>/, "").replace(/<\/svg>\s*$/, "").replace(/<!--[\s\S]*?-->/g, "");
const white = inner.replace(/#2563EB|#15803D/g, "#FFFFFF");

// mark (64 units) scaled into a square tile of `size`, occupying `fill` of it, on an optional background
function tile(body, { bg = null, radius = 0, fill = 1 } = {}) {
  const s = 64 * fill, off = (64 - s) / 2;
  const back = bg ? `<rect width="64" height="64" rx="${radius}" fill="${bg}"/>` : "";
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">${back}` +
    `<g transform="translate(${off} ${off}) scale(${fill})">${body}</g></svg>`;
}

function png(svg, size, name) {
  const out = new Resvg(svg, { fitTo: { mode: "width", value: size } }).render().asPng();
  fs.writeFileSync(path.join(OUT, name), out);
}

const appIcon = tile(white, { bg: BLUE, radius: 14, fill: 0.7 });   // rounded tile, for tabs/shortcuts
const fullBleed = tile(white, { bg: BLUE, fill: 0.6 });             // maskable + iOS (OS applies its own mask)

fs.writeFileSync(path.join(OUT, "mark.svg"), mark);
fs.writeFileSync(path.join(OUT, "favicon.svg"), tile(inner, { fill: 1 }));
png(tile(inner), 32, "favicon-32.png");
png(appIcon, 192, "icon-192.png");
png(appIcon, 512, "icon-512.png");
png(fullBleed, 512, "maskable-512.png");
png(fullBleed, 180, "apple-touch-icon.png");
console.log("brand assets written to app/static/brand");
