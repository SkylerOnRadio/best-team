import type { ReactNode } from "react";

export default function Badge({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold tracking-[0.16em] uppercase ${className}`}
    >
      {children}
    </span>
  );
}
