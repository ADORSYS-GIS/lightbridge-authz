import { Route, Routes } from "react-router";
import { PlaceholderPage } from "./routes/placeholder-page";

// Route set kept deliberately minimal and honest about what exists today (#442's scope
// note): exactly one real page, rendered for the root path AND as the catch-all for any
// other client-side path -- this SPA does not yet own `/login`, `/authorize`,
// `/callback`, or any other route those belong to #424/#425/#441/#443, not this
// scaffold. Server-side, every one of those protocol routes is already excluded from
// ever reaching this SPA fallback in the first place (build_idp_router mounts them
// ahead of the static fallback -- crates/lightbridge-authz-rest/src/lib.rs); this
// catch-all only ever sees paths the Rust router has already decided are NOT a protocol
// route.
function App() {
  return (
    <Routes>
      <Route path="/" element={<PlaceholderPage />} />
      <Route path="*" element={<PlaceholderPage />} />
    </Routes>
  );
}

export default App;
