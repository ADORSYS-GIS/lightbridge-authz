import { Disclosure, DisclosureButton, DisclosurePanel } from "@headlessui/react";

// Headless UI as plumbing only (accessible expand/collapse behavior -- keyboard
// navigation, aria-expanded wiring, focus management), styled with plain Tailwind
// utilities and daisyUI's semantic color tokens -- NOT daisyUI's `.btn` component
// class. See notice-panel.tsx's doc comment for why: `.btn` is one of the daisyUI 5
// component classes that unconditionally sets a `data:image/svg+xml` `background-image`
// (`fx-noise`), which `default-src 'self'` (no `data:` carve-out, ADR-0021 Decision 10)
// blocks and logs as a CSP violation on every load -- found via real browser
// verification in PR #446.
export function ScopeDisclosure() {
  return (
    <Disclosure as="div" className="mt-4">
      <DisclosureButton className="rounded px-3 py-1 text-sm hover:bg-base-content/10">
        What is this page?
      </DisclosureButton>
      <DisclosurePanel className="pt-2 text-sm opacity-80">
        This page exists to prove authz-idp serves its own static build, same-origin (ADR-0021). The
        sign-in flow itself -- redirecting to Keycloak, completing the session, returning to the
        requesting client -- is not implemented yet. See:
        <ul className="list-disc pl-5 mt-1">
          <li>#424 -- the RP leg to Keycloak</li>
          <li>#425 -- GET /authorize</li>
          <li>#441, #443 -- session creation and the __Host- cookie</li>
        </ul>
      </DisclosurePanel>
    </Disclosure>
  );
}
