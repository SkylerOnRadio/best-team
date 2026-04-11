import { type ReactNode, useEffect, useRef, useState } from "react";

export default function ScrollReveal({
  children,
  className = "",
  threshold = 0.16,
  rootMargin = "0px 0px -28px 0px",
  delayMs = 0,
}: {
  children: ReactNode;
  className?: string;
  threshold?: number;
  rootMargin?: string;
  delayMs?: number;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const target = ref.current;
    if (!target) return;

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting) {
          setIsVisible(true);
          observer.disconnect();
        }
      },
      { threshold, rootMargin },
    );

    observer.observe(target);
    return () => observer.disconnect();
  }, [threshold, rootMargin]);

  return (
    <div
      ref={ref}
      className={`section-reveal ${isVisible ? "section-reveal--visible" : ""} ${className}`}
      style={{ transitionDelay: `${delayMs}ms` }}
    >
      {children}
    </div>
  );
}
