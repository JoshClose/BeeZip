// What a job does, as BeeZip's comb (packaging/brand): extracting lifts the ink cell out of the
// comb (comb-lifted.svg), compressing sets it back in (comb-placing.svg), and testing is the
// whole comb (comb-rosette.svg). While the job runs the cell moves, out or in, over and over;
// afterwards it rests where the job left it. The motion is in index.css, and stops for people
// who ask for less motion.
import { cn } from "../lib/cn";

export type MarkKind = "extract" | "compress" | "test";
export type MarkState = "running" | "done" | "failed" | "cancelled";

/** The mark for a command: what comes out of an archive, what goes in, or neither. */
export function markKind(command: string): MarkKind {
  switch (command) {
    case "archive.extract":
    case "stream.decompress":
      return "extract";
    case "archive.create":
    case "archive.add":
    case "archive.convert":
    case "stream.compress":
      return "compress";
    default:
      return "test";
  }
}

const CELL = "0,-15 13,-7.5 13,7.5 0,15 -13,7.5 -13,-7.5";
const SLOT = "0,-13.5 11.7,-6.75 11.7,6.75 0,13.5 -11.7,6.75 -11.7,-6.75";
const AMBER = "#E0A21A";
const DEEP = "#9A6700";
const INK = "var(--ink)";

/** The comb's cells, as the brand marks place them: the centre and six around it. */
const AT = {
  centre: [60, 60],
  right: [89.4, 60],
  left: [30.6, 60],
  upLeft: [45.3, 34.5],
  upRight: [74.7, 34.5],
  downLeft: [45.3, 85.5],
  downRight: [74.7, 85.5],
} as const;
type Place = keyof typeof AT;

/** comb-lifted's and comb-placing's six cells; the up-right one is the cell that moves. */
const AROUND: [Place, string][] = [
  ["centre", DEEP],
  ["right", AMBER],
  ["left", AMBER],
  ["upLeft", AMBER],
  ["downRight", AMBER],
  ["downLeft", AMBER],
];

/** comb-rosette's seven. */
const ROSETTE: [Place, string][] = [
  ["centre", INK],
  ["right", AMBER],
  ["upRight", DEEP],
  ["upLeft", AMBER],
  ["left", DEEP],
  ["downLeft", AMBER],
  ["downRight", DEEP],
];

const at = (p: Place) => `translate(${AT[p][0]} ${AT[p][1]})`;

export function CombMark({ kind, state, className }: { kind: MarkKind; state: MarkState; className?: string }) {
  const cells = kind === "test" ? ROSETTE : AROUND;
  return (
    <svg viewBox="0 0 120 120" className={cn("comb-mark", className)} data-kind={kind} data-state={state} aria-hidden="true" focusable="false">
      {cells.map(([p, fill]) => (
        <polygon key={p} className="comb-fixed" points={CELL} transform={at(p)} style={{ fill }} />
      ))}
      {kind !== "test" && (
        <>
          {kind === "compress" && state === "running" && (
            <polygon className="comb-slot" points={SLOT} transform={at("upRight")} fill="none" stroke={AMBER} strokeWidth={3} strokeDasharray="5 3.4" strokeLinejoin="round" />
          )}
          <g className="comb-cell">
            <polygon points={CELL} transform={at("upRight")} style={{ fill: INK }} />
          </g>
        </>
      )}
    </svg>
  );
}
