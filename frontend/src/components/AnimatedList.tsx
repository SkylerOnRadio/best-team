import {
  type MouseEventHandler,
  type ReactNode,
  useCallback,
  useEffect,
  useRef,
  useState,
  type UIEvent,
} from "react";
import { motion, useInView } from "motion/react";

interface AnimatedItemProps {
  children: ReactNode;
  delay?: number;
  index: number;
  onMouseEnter?: MouseEventHandler<HTMLDivElement>;
  onClick?: MouseEventHandler<HTMLDivElement>;
}

function AnimatedItem({
  children,
  delay = 0,
  index,
  onMouseEnter,
  onClick,
}: AnimatedItemProps) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { amount: 0.45, once: false });

  return (
    <motion.div
      ref={ref}
      data-index={index}
      onMouseEnter={onMouseEnter}
      onClick={onClick}
      initial={{ scale: 0.92, opacity: 0 }}
      animate={inView ? { scale: 1, opacity: 1 } : { scale: 0.92, opacity: 0 }}
      transition={{ duration: 0.22, delay }}
      className="mb-2 cursor-pointer"
    >
      {children}
    </motion.div>
  );
}

interface AnimatedListProps {
  items: string[];
  onItemSelect?: (item: string, index: number) => void;
  showGradients?: boolean;
  enableArrowNavigation?: boolean;
  className?: string;
  itemClassName?: string;
  displayScrollbar?: boolean;
  initialSelectedIndex?: number;
  selectedIndex?: number;
  renderItem?: (item: string, index: number, selected: boolean) => ReactNode;
}

export default function AnimatedList({
  items,
  onItemSelect,
  showGradients = true,
  enableArrowNavigation = true,
  className = "",
  itemClassName = "",
  displayScrollbar = true,
  initialSelectedIndex = -1,
  selectedIndex,
  renderItem,
}: AnimatedListProps) {
  const listRef = useRef<HTMLDivElement>(null);
  const [internalSelected, setInternalSelected] =
    useState<number>(initialSelectedIndex);
  const [keyboardNav, setKeyboardNav] = useState<boolean>(false);
  const [topGradientOpacity, setTopGradientOpacity] = useState<number>(0);
  const [bottomGradientOpacity, setBottomGradientOpacity] = useState<number>(1);

  const activeIndex = selectedIndex ?? internalSelected;

  useEffect(() => {
    if (selectedIndex === undefined) return;
    setInternalSelected(selectedIndex);
  }, [selectedIndex]);

  const handleItemMouseEnter = useCallback((index: number) => {
    setInternalSelected(index);
  }, []);

  const handleItemClick = useCallback(
    (item: string, index: number) => {
      setInternalSelected(index);
      if (onItemSelect) {
        onItemSelect(item, index);
      }
    },
    [onItemSelect],
  );

  const handleScroll = (e: UIEvent<HTMLDivElement>) => {
    const { scrollTop, scrollHeight, clientHeight } =
      e.target as HTMLDivElement;
    setTopGradientOpacity(Math.min(scrollTop / 50, 1));
    const bottomDistance = scrollHeight - (scrollTop + clientHeight);
    setBottomGradientOpacity(
      scrollHeight <= clientHeight ? 0 : Math.min(bottomDistance / 50, 1),
    );
  };

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
      if (!enableArrowNavigation || items.length === 0) return;

      if (e.key === "ArrowDown") {
        e.preventDefault();
        setKeyboardNav(true);
        setInternalSelected((prev) => Math.min(prev + 1, items.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setKeyboardNav(true);
        setInternalSelected((prev) => Math.max(prev - 1, 0));
      } else if (e.key === "Enter") {
        if (activeIndex >= 0 && activeIndex < items.length) {
          e.preventDefault();
          if (onItemSelect) {
            onItemSelect(items[activeIndex], activeIndex);
          }
        }
      }
    },
    [enableArrowNavigation, items, activeIndex, onItemSelect],
  );

  useEffect(() => {
    if (!keyboardNav || activeIndex < 0 || !listRef.current) return;
    const container = listRef.current;
    const selectedItem = container.querySelector(
      `[data-index="${activeIndex}"]`,
    ) as HTMLElement | null;

    if (selectedItem) {
      const extraMargin = 48;
      const containerScrollTop = container.scrollTop;
      const containerHeight = container.clientHeight;
      const itemTop = selectedItem.offsetTop;
      const itemBottom = itemTop + selectedItem.offsetHeight;

      if (itemTop < containerScrollTop + extraMargin) {
        container.scrollTo({ top: itemTop - extraMargin, behavior: "smooth" });
      } else if (
        itemBottom >
        containerScrollTop + containerHeight - extraMargin
      ) {
        container.scrollTo({
          top: itemBottom - containerHeight + extraMargin,
          behavior: "smooth",
        });
      }
    }
    setKeyboardNav(false);
  }, [activeIndex, keyboardNav]);

  const defaultRenderer = (item: string, index: number, selected: boolean) => (
    <div
      className={`rounded-lg border p-3 text-sm ${
        selected
          ? "border-fuchsia-300/45 bg-fuchsia-400/20 text-white"
          : "border-white/10 bg-slate-950/40 text-slate-200"
      } ${itemClassName}`}
    >
      <p className="m-0">{item}</p>
    </div>
  );

  return (
    <div className={`relative w-full ${className}`}>
      <div
        ref={listRef}
        className={`max-h-[220px] overflow-y-auto p-1 ${
          displayScrollbar
            ? "[&::-webkit-scrollbar]:w-[8px] [&::-webkit-scrollbar-track]:bg-[var(--list-surface)] [&::-webkit-scrollbar-thumb]:bg-[var(--list-thumb)] [&::-webkit-scrollbar-thumb]:rounded-[4px]"
            : ""
        }`}
        onScroll={handleScroll}
        onKeyDown={handleKeyDown}
        tabIndex={0}
        style={{
          scrollbarWidth: displayScrollbar ? "thin" : "none",
          scrollbarColor: "var(--list-thumb) var(--list-surface)",
        }}
      >
        {items.map((item, index) => (
          <AnimatedItem
            key={`${item}-${index}`}
            delay={0.06}
            index={index}
            onMouseEnter={() => handleItemMouseEnter(index)}
            onClick={() => handleItemClick(item, index)}
          >
            {renderItem
              ? renderItem(item, index, activeIndex === index)
              : defaultRenderer(item, index, activeIndex === index)}
          </AnimatedItem>
        ))}
      </div>

      {showGradients ? (
        <>
          <div
            className="pointer-events-none absolute left-0 right-0 top-0 h-[40px] bg-gradient-to-b from-[var(--list-surface)] to-transparent transition-opacity duration-300"
            style={{ opacity: topGradientOpacity }}
          />
          <div
            className="pointer-events-none absolute bottom-0 left-0 right-0 h-[70px] bg-gradient-to-t from-[var(--list-surface)] to-transparent transition-opacity duration-300"
            style={{ opacity: bottomGradientOpacity }}
          />
        </>
      ) : null}
    </div>
  );
}
