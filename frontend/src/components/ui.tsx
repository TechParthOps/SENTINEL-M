import type { ReactNode } from "react";

export function Card({ title, subtitle, right, children, className }: {
  title?: string;
  subtitle?: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-xl border border-sentinel-border bg-sentinel-surface/80 ${className ?? ""}`}>
      {(title || right) && (
        <header className="flex items-start justify-between gap-3 border-b border-sentinel-border/70 px-4 py-3">
          <div>
            {title && <h2 className="text-sm font-semibold tracking-wide text-slate-100">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-xs text-sentinel-muted">{subtitle}</p>}
          </div>
          {right}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function Badge({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${className ?? ""}`}>
      {children}
    </span>
  );
}

export function Button({ children, onClick, disabled, variant = "primary", type = "button", title }: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "primary" | "ghost" | "danger";
  type?: "button" | "submit";
  title?: string;
}) {
  const styles: Record<string, string> = {
    primary: "bg-cyan-600 hover:bg-cyan-500 text-white border-cyan-500/50",
    ghost: "bg-transparent hover:bg-white/5 text-slate-300 border-sentinel-border",
    danger: "bg-red-700/80 hover:bg-red-600 text-white border-red-500/50",
  };
  return (
    <button
      type={type}
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={`rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors disabled:opacity-40 ${styles[variant]}`}
    >
      {children}
    </button>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 text-sm text-sentinel-muted">
      <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-sentinel-accent border-t-transparent" />
      {label ?? "Loading…"}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-8 text-center text-sm text-sentinel-muted">{children}</p>;
}

export function ErrorBox({ children }: { children: ReactNode }) {
  return (
    <p className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">
      {children}
    </p>
  );
}

export function Table({ head, rows }: { head: string[]; rows: ReactNode[][] }) {
  return (
    <table className="w-full border-collapse text-sm">
      <thead>
        <tr>
          {head.map((h) => (
            <th key={h} className="border-b border-sentinel-border px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-sentinel-muted">
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row, i) => (
          <tr key={i} className="odd:bg-white/[0.02] hover:bg-cyan-500/[0.06]">
            {row.map((cell, j) => (
              <td key={j} className="border-b border-sentinel-border/40 px-3 py-2 align-top">
                {cell}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}