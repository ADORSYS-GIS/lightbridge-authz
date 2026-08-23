import { Route, Routes } from "react-router";
import { PlaceholderPage } from "./routes/placeholder-page";

// Route set kept deliberately minimal and honest about what exists today (#442's scope
// note): exactly one real page, rendered for the root path AND as the catch-all for any
// other client-side path -- this SPA does not yet own `/login`, `/authorize`,
// `/callback`, or any other route those belong to #424/#425/#441/#443, not this
// scaffold. Server-side, every one of those protocol routes is already excluded from
// ever reaching this SPA in the first place: this app is built with Vite base:
// "/ui/" and served only under authz-idp's /ui path prefix (build_idp_router nests it
// at /ui -- crates/lightbridge-authz-rest/src/lib.rs), a disjoint path space from every
// protocol route, so this catch-all only ever sees paths already under /ui that the
// Rust router has decided are NOT a real static file.
function App() {
  return (
    <Routes>
      <Route path="/" element={<PlaceholderPage />} />
      <Route path="*" element={<PlaceholderPage />} />
    </Routes>
  );
}

export default App;
