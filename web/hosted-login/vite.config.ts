import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { VitePWA } from "vite-plugin-pwa";

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    VitePWA({
      registerType: "autoUpdate",
      // Hand-written sw.ts (src/sw.ts) instead of the default generateSW strategy: see
      // that file's own doc comment for why -- generateSW's `navigateFallback` mechanism
      // is fundamentally cache-first for whatever URL it targets, which conflicts with
      // Decision 10's `no-cache` posture for index.html (ADR-0021, #442).
      strategies: "injectManifest",
      srcDir: "src",
      filename: "sw.ts",
      injectManifest: {
        // Precache ONLY the content-hashed, immutably-cached bundle -- never index.html
        // or any other unhashed file. A hash change is a different URL, so this list can
        // never go stale the way caching index.html itself would.
        globPatterns: ["assets/**/*.{js,css}"],
      },
      // No web app manifest: this surface has no decided visual identity yet (icons,
      // name, theme color are all design decisions this scaffold explicitly defers --
      // see App.tsx's own comment), and installability was never part of the ask (the
      // PWA plugin is here for asset caching only, per PR #446's brief).
      manifest: false,
      devOptions: {
        // Never register a SW against the dev server -- only ever verify against a real
        // production build, the same caution Decision 10's Risk table already calls out
        // for the CSP ("verify against an actual production vite build output, not
        // dev-mode HMR injection").
        enabled: false,
      },
    }),
  ],
});
