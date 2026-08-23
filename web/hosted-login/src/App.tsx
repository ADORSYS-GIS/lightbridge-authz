// PLACEHOLDER PAGE -- #442 scaffolds the static build + serving infrastructure only
// (ADR-0021 Decisions 1 and 10). It deliberately does not implement:
//   - the RP leg to Keycloak (#424)
//   - GET /authorize (#425)
//   - session creation / the __Host- cookie (#441, #443)
// Nothing on this page calls any of those endpoints yet. The visual direction for this
// surface has not been decided (see AGENTS.md's design-philosophy note on grounding UI in
// references before styling) -- this is intentionally plain, not a first pass at a real
// design.

function App() {
  return (
    <main
      style={{
        display: "flex",
        minHeight: "100vh",
        alignItems: "center",
        justifyContent: "center",
        padding: "2rem",
      }}
    >
      <div
        style={{
          maxWidth: "28rem",
          border: "1px dashed #888",
          borderRadius: "0.5rem",
          padding: "1.5rem",
        }}
      >
        <p style={{ margin: 0, fontWeight: 600 }}>
          authz-idp hosted login -- placeholder
        </p>
        <p style={{ marginTop: "0.75rem" }}>
          This page exists to prove the static build is served by authz-idp itself. The
          sign-in flow (redirecting to Keycloak, completing the session, returning to the
          requesting client) is not implemented here yet -- see ADR-0021 and issues
          #424/#425/#441/#443.
        </p>
      </div>
    </main>
  );
}

export default App;
