import { registerSW } from "virtual:pwa-register";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import App from "./App.tsx";
import "./index.css";

// ADR-0021 Decision 10 (#442): registers the precache-only service worker (src/sw.ts).
// `autoUpdate` means a new SW activates and takes over as soon as it finishes
// installing -- no user prompt, no stale version pinned indefinitely. That matters
// specifically on this origin: a pinned stale SW on a login page is a lockout, not a
// convenience. See src/sw.ts for what this SW does and, just as importantly, does not
// do (no navigation interception, no caching of index.html or any protocol route).
registerSW({ immediate: true });

// biome-ignore lint/style/noNonNullAssertion: vite's own index.html always provides #root
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
);
