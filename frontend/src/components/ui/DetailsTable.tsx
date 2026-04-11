import type { ReactNode } from "react";

export default function DetailsTable({
  headers,
  rows,
  emptyText,
}: {
  headers: string[];
  rows: ReactNode[];
  emptyText: string;
}) {
  return (
    <div className="overflow-hidden rounded-3xl border border-white/10 bg-slate-950/45">
      <div className="max-h-[32rem] overflow-auto">
        <table className="min-w-full border-separate border-spacing-0 text-left text-sm">
          <thead className="sticky top-0 z-10 bg-slate-950/95 text-[11px] uppercase tracking-[0.2em] text-slate-400">
            <tr>
              {headers.map((header) => (
                <th
                  key={header}
                  className="border-b border-white/10 px-4 py-3 font-semibold"
                >
                  {header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length > 0 ? (
              rows
            ) : (
              <tr>
                <td
                  className="px-4 py-8 text-center text-slate-400"
                  colSpan={headers.length}
                >
                  {emptyText}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
