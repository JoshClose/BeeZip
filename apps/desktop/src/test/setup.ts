// jsdom has no layout, observers or clipboard; the components need stand-ins.
import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

afterEach(() => cleanup());

class NoResize {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= NoResize as unknown as typeof ResizeObserver;
Element.prototype.scrollIntoView ??= function () {};
Element.prototype.scrollTo ??= function () {} as typeof Element.prototype.scrollTo;
Object.defineProperty(navigator, "clipboard", {
  value: { writeText: vi.fn(async () => {}) },
  configurable: true,
});
