// The benchmark's chart (docs/M6.md §7): the packed size upwards (smaller is higher) against
// the speed across, on a log scale. A colour per codec, its levels joined and labelled, and a
// marker for the threads. Drawn here in SVG, so no chart library joins the bundle; the table
// under it holds the same numbers and is what a screen reader reads. Its looks wait for the
// final pass.
import { useMemo, useState } from "react";
import type { BenchCell, CodecName } from "../../gen/commands";
import { formatSize } from "../../lib/format";

/** A codec family shares a colour, since its levels are one algorithm: eight slots in a fixed
 * order, by codec, never by rank. Unix compress has none of its own. */
const SLOT: Record<CodecName, number | null> = {
  gzip: 1,
  zlib: 1,
  deflate: 1,
  bzip2: 2,
  xz: 3,
  lzma: 3,
  lzip: 3,
  zstd: 4,
  lz4: 5,
  brotli: 6,
  snappy: 7,
  lzop: 8,
  compress: null,
};

export function codecColor(codec: CodecName): string {
  const slot = SLOT[codec];
  return slot === null ? "var(--muted)" : `var(--series-${slot})`;
}

export type Axis = "compress" | "decompress";

/** `1`, `4` or `all`. */
export function threadsLabel(threads: number, cpus: number): string {
  return threads > 1 && threads === cpus ? "all" : String(threads);
}

/** `xz -6, all threads`; `lz4`. Threads are named only past one. */
export function cellLabel(c: BenchCell, cpus: number): string {
  const level = c.level === null ? "" : ` -${c.level}`;
  const t = threadsLabel(c.threads, cpus);
  const threads = c.threads === 1 ? "" : t === "all" ? ", all threads" : `, ${t} threads`;
  return `${c.codec}${level}${threads}`;
}

export function formatMbps(v: number): string {
  if (v <= 0) return "";
  return v >= 100 ? `${Math.round(v).toLocaleString()} MB/s` : `${v.toFixed(1)} MB/s`;
}

export function formatPercent(ratio: number): string {
  return `${(ratio * 100).toFixed(1)}%`;
}

const W = 640;
const H = 340;
const M = { left: 52, right: 20, top: 14, bottom: 42 };

type Point = { cell: BenchCell; index: number; x: number; y: number };

/** Powers of ten around `lo`–`hi`. */
function decades(lo: number, hi: number): [number, number] {
  const a = Math.floor(Math.log10(lo));
  const b = Math.max(a + 1, Math.ceil(Math.log10(hi)));
  return [a, b];
}

function Marker({ threads, cpus, x, y, color }: { threads: number; cpus: number; x: number; y: number; color: string }) {
  // A surface ring keeps overlapping markers apart.
  const ring = { stroke: "var(--panel)", strokeWidth: 2, fill: color };
  if (threads === 1) return <circle cx={x} cy={y} r={4.5} {...ring} />;
  if (threads > 1 && threads === cpus) return <path d={`M${x} ${y - 6}L${x + 6} ${y}L${x} ${y + 6}L${x - 6} ${y}Z`} {...ring} />;
  return <rect x={x - 4.5} y={y - 4.5} width={9} height={9} {...ring} />;
}

export function BenchChart({ cells, cpus }: { cells: BenchCell[]; cpus: number }) {
  const [axis, setAxis] = useState<Axis>("compress");
  const [hover, setHover] = useState<number>();

  const plot = useMemo(() => {
    const speed = (c: BenchCell) => (axis === "compress" ? c.compress_mbps : c.decompress_mbps);
    const ok = cells.map((cell, index) => ({ cell, index })).filter(({ cell }) => cell.error === null && speed(cell) > 0);
    if (ok.length === 0) return undefined;
    const speeds = ok.map(({ cell }) => speed(cell));
    const sizes = ok.map(({ cell }) => cell.ratio * 100);
    const [d0, d1] = decades(Math.min(...speeds), Math.max(...speeds));
    let y0 = Math.floor(Math.min(...sizes) / 10) * 10;
    let y1 = Math.ceil(Math.max(...sizes) / 10) * 10;
    if (y1 - y0 < 10) [y0, y1] = [Math.max(0, y0 - 5), y0 + 10];
    const sx = (v: number) => M.left + ((Math.log10(v) - d0) / (d1 - d0)) * (W - M.left - M.right);
    // Smaller is higher: the best sizes at the top.
    const sy = (pct: number) => M.top + ((pct - y0) / (y1 - y0)) * (H - M.top - M.bottom);
    const points: Point[] = ok.map(({ cell, index }) => ({ cell, index, x: sx(speed(cell)), y: sy(cell.ratio * 100) }));
    // A line per codec and thread count, through its levels in order.
    const series = new Map<string, Point[]>();
    for (const p of points) {
      const key = `${p.cell.codec}/${p.cell.threads}`;
      series.set(key, [...(series.get(key) ?? []), p]);
    }
    for (const line of series.values()) line.sort((a, b) => (a.cell.level ?? 0) - (b.cell.level ?? 0));
    const step = y1 - y0 > 50 ? 20 : 10;
    const yTicks: number[] = [];
    for (let t = Math.ceil(y0 / step) * step; t <= y1; t += step) yTicks.push(t);
    const xTicks: number[] = [];
    for (let d = d0; d <= d1; d++) xTicks.push(10 ** d);
    return { points, series: [...series.values()], sx, sy, xTicks, yTicks };
  }, [cells, axis]);

  const codecs = [...new Set(cells.filter((c) => c.error === null).map((c) => c.codec))];
  const threaded = cells.some((c) => c.threads > 1);
  const hovered = plot?.points.find((p) => p.index === hover);

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <div className="flex rounded-[5px] border border-rule" role="group" aria-label="Speed across">
          {(["compress", "decompress"] as const).map((a) => (
            <button
              key={a}
              type="button"
              aria-pressed={axis === a}
              onClick={() => setAxis(a)}
              className={axis === a ? "h-7 bg-amber-wash px-2.5 font-semibold" : "h-7 px-2.5 text-muted hover:bg-sunken"}
            >
              {a === "compress" ? "Compression speed" : "Decompression speed"}
            </button>
          ))}
        </div>
        <ul className="flex flex-wrap gap-x-3 gap-y-0.5 text-[12px]" aria-label="Codecs">
          {codecs.map((c) => (
            <li key={c} className="flex items-center gap-1">
              <span className="inline-block size-2.5 rounded-full" style={{ background: codecColor(c) }} />
              {c}
            </li>
          ))}
        </ul>
        {threaded && <p className="text-[12px] text-muted">● 1 thread · ■ some threads · ◆ all threads</p>}
      </div>

      <div className="relative">
        <svg viewBox={`0 0 ${W} ${H}`} className="block w-full" aria-hidden="true" data-testid="bench-chart">
          {!plot && (
            <text x={W / 2} y={H / 2} textAnchor="middle" fill="var(--muted)" fontSize={13}>
              Each cell shows here as it finishes.
            </text>
          )}
          {plot && (
            <>
              {plot.yTicks.map((t) => (
                <g key={`y${t}`}>
                  <line x1={M.left} x2={W - M.right} y1={plot.sy(t)} y2={plot.sy(t)} stroke="var(--rule)" />
                  <text x={M.left - 6} y={plot.sy(t) + 4} textAnchor="end" fontSize={11} fill="var(--muted)">
                    {t}%
                  </text>
                </g>
              ))}
              {plot.xTicks.map((t) => (
                <g key={`x${t}`}>
                  <line x1={plot.sx(t)} x2={plot.sx(t)} y1={M.top} y2={H - M.bottom} stroke="var(--rule)" />
                  <text x={plot.sx(t)} y={H - M.bottom + 15} textAnchor="middle" fontSize={11} fill="var(--muted)">
                    {t.toLocaleString()}
                  </text>
                </g>
              ))}
              <text x={(M.left + W - M.right) / 2} y={H - 6} textAnchor="middle" fontSize={12} fill="var(--muted)">
                {axis === "compress" ? "Compression" : "Decompression"} speed, MB/s (log scale)
              </text>
              <text transform={`translate(13 ${(M.top + H - M.bottom) / 2}) rotate(-90)`} textAnchor="middle" fontSize={12} fill="var(--muted)">
                Size after compression (smaller is higher)
              </text>
              {plot.series.map((line) => {
                const first = line[0];
                const last = line[line.length - 1];
                return (
                  <g key={`${first.cell.codec}/${first.cell.threads}`}>
                    {line.length > 1 && (
                      <polyline
                        points={line.map((p) => `${p.x},${p.y}`).join(" ")}
                        fill="none"
                        stroke={codecColor(first.cell.codec)}
                        strokeWidth={2}
                        strokeLinejoin="round"
                      />
                    )}
                    {line.map((p) => (
                      <g key={p.index}>
                        <Marker threads={p.cell.threads} cpus={cpus} x={p.x} y={p.y} color={codecColor(p.cell.codec)} />
                        {p.cell.level !== null && line.length > 1 && (
                          <text x={p.x + 7} y={p.y + 13} fontSize={10} fill="var(--muted)">
                            {p.cell.level}
                          </text>
                        )}
                      </g>
                    ))}
                    <text x={last.x + 8} y={last.y - 6} fontSize={11} fill="var(--ink)">
                      {first.cell.codec}
                      {first.cell.threads > 1 ? ` ×${threadsLabel(first.cell.threads, cpus)}` : ""}
                    </text>
                  </g>
                );
              })}
              {/* Hit targets bigger than the markers, on top. */}
              {plot.points.map((p) => (
                <circle
                  key={`hit${p.index}`}
                  cx={p.x}
                  cy={p.y}
                  r={10}
                  fill="transparent"
                  onMouseEnter={() => setHover(p.index)}
                  onMouseLeave={() => setHover((h) => (h === p.index ? undefined : h))}
                  data-testid={`bench-point-${p.index}`}
                />
              ))}
            </>
          )}
        </svg>
        {hovered && (
          <div
            role="tooltip"
            className="pointer-events-none absolute z-10 w-max max-w-64 rounded-[5px] border border-rule bg-panel px-2 py-1.5 text-[12px] shadow-[0_4px_14px_rgba(0,0,0,0.18)]"
            style={{
              left: `${(hovered.x / W) * 100}%`,
              top: `${(hovered.y / H) * 100}%`,
              transform: `translate(${hovered.x > W * 0.6 ? "calc(-100% - 12px)" : "12px"}, -50%)`,
            }}
          >
            <p className="font-semibold">{cellLabel(hovered.cell, cpus)}</p>
            <p>
              {formatPercent(hovered.cell.ratio)} of the size ({formatSize(hovered.cell.packed_bytes)})
            </p>
            <p>
              Compressing: {formatMbps(hovered.cell.compress_mbps)}, {formatSize(hovered.cell.compress_mem)} of memory
            </p>
            <p>
              Decompressing: {formatMbps(hovered.cell.decompress_mbps)}, {formatSize(hovered.cell.decompress_mem)} of memory
            </p>
          </div>
        )}
      </div>

      <BenchTable cells={cells} cpus={cpus} />
    </div>
  );
}

/** The chart's numbers, one row a cell, failures included. */
export function BenchTable({ cells, cpus }: { cells: BenchCell[]; cpus: number }) {
  const th = "px-2 py-1 text-left font-normal text-muted";
  const td = "px-2 py-0.5 tabular whitespace-nowrap";
  return (
    <div className="max-h-56 overflow-auto rounded-[5px] border border-rule">
      <table className="selectable w-full text-[12px]">
        <caption className="sr-only">Benchmark results</caption>
        <thead className="sticky top-0 bg-panel">
          <tr className="border-b border-rule">
            <th className={th}>Codec</th>
            <th className={th}>Level</th>
            <th className={th}>Threads</th>
            <th className={th}>Size</th>
            <th className={th}>Compressing</th>
            <th className={th}>Decompressing</th>
            <th className={th}>Memory compressing</th>
            <th className={th}>Memory decompressing</th>
            <th className={th}>Time</th>
          </tr>
        </thead>
        <tbody>
          {cells.map((c, i) => (
            <tr key={i} className="border-t border-rule first:border-t-0">
              <td className={td}>
                <span className="mr-1.5 inline-block size-2 rounded-full" style={{ background: codecColor(c.codec) }} aria-hidden="true" />
                {c.codec}
              </td>
              <td className={td}>{c.level ?? ""}</td>
              <td className={td}>{threadsLabel(c.threads, cpus)}</td>
              {c.error !== null ? (
                <td className={`${td} whitespace-normal text-danger`} colSpan={6}>
                  Failed: {c.error}
                </td>
              ) : (
                <>
                  <td className={td}>{formatPercent(c.ratio)}</td>
                  <td className={td}>{formatMbps(c.compress_mbps)}</td>
                  <td className={td}>{formatMbps(c.decompress_mbps)}</td>
                  <td className={td}>{formatSize(c.compress_mem)}</td>
                  <td className={td}>{formatSize(c.decompress_mem)}</td>
                  <td className={td}>{(c.ms / 1000).toFixed(2)} s</td>
                </>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
