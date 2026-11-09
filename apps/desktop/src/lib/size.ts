// An element's size, kept up to date, for layouts that work out what fits.
import { type RefCallback, useCallback, useRef, useState } from "react";

export type Size = { width: number; height: number };

/** The size, in CSS pixels with borders, of the element the returned ref is put on, or of its
 * parent with `parent`; 0 × 0 until it's measured (and in jsdom, which has no layout). The
 * first measure comes before the first paint. Works for an element that comes and goes. */
export function useSize<T extends HTMLElement>(parent = false): [RefCallback<T>, Size] {
  const [size, setSize] = useState<Size>({ width: 0, height: 0 });
  const observer = useRef<ResizeObserver | undefined>(undefined);
  const ref = useCallback(
    (el: T | null) => {
      observer.current?.disconnect();
      observer.current = undefined;
      const target = parent ? el?.parentElement : el;
      if (!target) return;
      const measure = () => {
        const r = target.getBoundingClientRect();
        const next = { width: Math.round(r.width), height: Math.round(r.height) };
        setSize((s) => (s.width === next.width && s.height === next.height ? s : next));
      };
      measure();
      observer.current = new ResizeObserver(measure);
      observer.current.observe(target);
    },
    [parent],
  );
  return [ref, size];
}
