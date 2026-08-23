import { cva, type VariantProps } from "class-variance-authority";
import type { ReactNode } from "react";
import { cn } from "../lib/cn";

// Plain Tailwind utilities + daisyUI's semantic color tokens (`base-*`, `info-*`), NOT
// daisyUI's `.alert` component class. Found by real CSP verification (PR #446): every
// daisyUI 5 component class in the `fx-noise`-referencing set (`alert`, `button`,
// `badge`, `checkbox`, `radio`, `toggle`, `fileinput`, `menu`, `svg`) unconditionally
// sets `background-image: none, var(--fx-noise)` -- a `data:image/svg+xml` URI --
// regardless of the active theme's `--noise` value (`--noise` only scales the
// *rendered size* of the effect via `background-size`, it does not gate whether the
// browser attempts to fetch the image at all). `default-src 'self'` has no `data:`
// carve-out (ADR-0021 Decision 10 specifies exactly `default-src 'self'; frame-ancestors
// 'none'`, nothing more), so any of those component classes gets its background image
// blocked and logs a CSP violation on every load. Fixed by using only daisyUI's
// utility-level color tokens (`base/colors.css` and `utilities/`, verified to carry no
// `fx-noise` reference), never the `fx-noise`-bearing component classes -- this is a
// bug fix, not a workaround: it keeps the CSP exactly as decided, at the cost of
// composing raw utilities instead of daisyUI's pre-built components, which is a smaller
// surface anyway (see this file's docstring on "plumbing, not a look").
const noticeVariants = cva("rounded-lg border p-4", {
  variants: {
    tone: {
      neutral: "border-info/30 bg-info/10 text-base-content",
    },
  },
  defaultVariants: {
    tone: "neutral",
  },
});

interface NoticePanelProps extends VariantProps<typeof noticeVariants> {
  children: ReactNode;
  className?: string;
}

export function NoticePanel({ tone, children, className }: NoticePanelProps) {
  return <div className={cn(noticeVariants({ tone }), className)}>{children}</div>;
}
