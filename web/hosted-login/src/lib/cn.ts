import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Composes conditional class names (clsx) and resolves conflicting Tailwind utility
 * classes in favor of the last one (tailwind-merge) -- the standard pairing so a
 * component's own default classes can be safely overridden by a caller-supplied
 * `className` without producing two conflicting utilities in the same `class`
 * attribute (e.g. `p-2 p-4` both applying, order-dependent on stylesheet order).
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
