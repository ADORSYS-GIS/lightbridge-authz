import { NoticePanel } from "../components/notice-panel";
import { ScopeDisclosure } from "../components/scope-disclosure";

// PLACEHOLDER PAGE -- #442 scaffolds the static build + serving infrastructure, the
// styling/PWA/router plumbing, and this page's shell only. It deliberately does not
// implement:
//   - the RP leg to Keycloak (#424)
//   - GET /authorize (#425)
//   - session creation / the __Host- cookie (#441, #443)
// Nothing on this page calls any of those endpoints yet. Rendered for every route this
// SPA owns today (there is exactly one) -- see src/App.tsx's router setup.
//
// The visual direction for this surface has not been decided (AGENTS.md's design
// philosophy: ground UI in references before styling; ADR-0008's dark direction governs
// the self-service app, not this one). daisyUI/Tailwind/cva/Headless UI are wired below
// as plumbing, proven functional, not as a first design pass -- picking an actual look
// is not this ticket's call to make.
export function PlaceholderPage() {
  return (
    <main className="flex min-h-screen items-center justify-center p-8">
      <div className="max-w-md">
        <NoticePanel>
          <span>
            <p className="font-semibold">authz-idp hosted login -- placeholder</p>
            <p className="mt-2">
              This page is served by authz-idp itself, same-origin, exactly as ADR-0021 requires.
              Sign-in is not implemented yet.
            </p>
          </span>
        </NoticePanel>
        <ScopeDisclosure />
      </div>
    </main>
  );
}
