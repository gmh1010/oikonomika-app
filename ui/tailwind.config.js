// Oikonomika design system ("Oikonomika Calm Finance", from the Google Stitch project) compiled at build time.
// No Tailwind CDN at runtime: the CSP forbids it and it would leak visitors to third parties.
const stitch = require("./stitch-colors.json");

// The accent is user-configurable (Settings) -> CSS variable holding "r g b".
const accent = "rgb(var(--accent) / <alpha-value>)";
const colors = Object.fromEntries(
  Object.entries(stitch).filter(([k]) => !/^(primary|on-primary|inverse-primary|surface-tint)/.test(k))
);

module.exports = {
  content: ["../app/templates/**/*.html", "../app/static/app.js", "../app/*.py"],
  // Three-state theme: <html class="dark"> forces dark, class="light" forces light, no class follows the OS.
  darkMode: ["variant", ["@media (prefers-color-scheme: dark) { &:not(.light *) }", "&:is(.dark *)"]],
  theme: {
    extend: {
      colors: {
        ...colors,
        primary: accent,
        "primary-container": accent,
        "on-primary": "#ffffff",
        "on-primary-container": "#ffffff",
      },
      fontFamily: { sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"] },
      fontSize: {
        "body-sm": ["12px", { lineHeight: "16px", fontWeight: "400" }],
        "body-md": ["14px", { lineHeight: "20px", fontWeight: "400" }],
        "body-lg": ["16px", { lineHeight: "24px", fontWeight: "400" }],
        "label-md": ["12px", { lineHeight: "16px", fontWeight: "500" }],
        "label-lg": ["14px", { lineHeight: "20px", fontWeight: "500" }],
        "title-md": ["16px", { lineHeight: "24px", fontWeight: "600" }],
        "amount-row": ["16px", { lineHeight: "24px", fontWeight: "600" }],
        "headline-md": ["20px", { lineHeight: "28px", fontWeight: "600" }],
        "headline-lg": ["24px", { lineHeight: "32px", letterSpacing: "-0.01em", fontWeight: "600" }],
        "display-lg-mobile": ["28px", { lineHeight: "36px", letterSpacing: "-0.01em", fontWeight: "600" }],
        "amount-display": ["32px", { lineHeight: "40px", letterSpacing: "-0.02em", fontWeight: "700" }],
        "display-lg": ["36px", { lineHeight: "44px", letterSpacing: "-0.02em", fontWeight: "600" }],
      },
      borderRadius: { DEFAULT: "0.25rem", lg: "0.5rem", xl: "0.75rem", "2xl": "1rem" },
      maxWidth: { content: "1100px" },
    },
  },
  plugins: [require("@tailwindcss/forms")],
};
