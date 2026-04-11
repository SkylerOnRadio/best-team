import { type ReactNode, useEffect, useRef, useState } from "react";
import BorderGlow from "../BorderGlow";

export default function SectionShell({
  title,
  subtitle,
  badge,
  children,
}: {
  title: string;
  subtitle?: string;
  badge?: ReactNode;
  children: ReactNode;
}) {
  const shellRef = useRef<HTMLElement | null>(null);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const target = shellRef.current;
    if (!target) return;

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting) {
          setIsVisible(true);
          observer.disconnect();
        }
      },
      { threshold: 0.16, rootMargin: "0px 0px -32px 0px" },
    );

    observer.observe(target);
    return () => observer.disconnect();
  }, []);

  return (
    <BorderGlow
      edgeSensitivity={30}
      glowColor="40 80 80"
      backgroundColor="var(--glow-bg)"
      borderRadius={28}
      glowRadius={40}
      glowIntensity={1}
      coneSpread={25}
      animated={false}
      colors={["#c084fc", "#f472b6", "#38bdf8"]}
      className={`w-full section-reveal ${isVisible ? "section-reveal--visible" : ""}`}
    >
      <section
        ref={shellRef}
        className="rounded-[28px] border border-white/10 bg-[var(--panel)] p-4 shadow-glow backdrop-blur-xl sm:p-6"
      >
        <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="font-display text-xl font-bold text-white sm:text-2xl">
              {title}
            </h2>
            {subtitle ? (
              <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-300">
                {subtitle}
              </p>
            ) : null}
          </div>
          {badge}
        </div>
        {children}
      </section>
    </BorderGlow>
  );
}
