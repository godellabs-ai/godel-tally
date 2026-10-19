"use client";

import React, { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { cn } from "@/lib/utils";

/** Gap between the trigger and the menu. */
const TRIGGER_GAP = 6;

/**
 * Portals a dropdown menu to <body> and pins it to the trigger with fixed positioning, so
 * ancestor `overflow-hidden` containers (cards, tables, modals) can never clip it.
 */
export function DropdownPopover({
  triggerRef,
  onClose,
  className,
  children,
}: {
  triggerRef: React.RefObject<HTMLElement | null>;
  onClose: () => void;
  className?: string;
  children: React.ReactNode;
}) {
  const menuRef = useRef<HTMLDivElement>(null);
  const [style, setStyle] = useState<React.CSSProperties>({});
  const [openUp, setOpenUp] = useState(false);

  useLayoutEffect(() => {
    const position = () => {
      const trigger = triggerRef.current;
      const menu = menuRef.current;
      if (!trigger || !menu) return;
      const rect = trigger.getBoundingClientRect();
      const menuHeight = menu.offsetHeight;
      const spaceBelow = window.innerHeight - rect.bottom;
      const up = spaceBelow < menuHeight + TRIGGER_GAP && rect.top > spaceBelow;
      setOpenUp(up);
      setStyle({
        position: "fixed",
        left: rect.left,
        width: Math.max(rect.width, 180),
        top: up ? rect.top - menuHeight - TRIGGER_GAP : rect.bottom + TRIGGER_GAP,
      });
    };
    position();
    window.addEventListener("scroll", position, true);
    window.addEventListener("resize", position);
    const observer = new ResizeObserver(position);
    if (menuRef.current) observer.observe(menuRef.current);
    return () => {
      window.removeEventListener("scroll", position, true);
      window.removeEventListener("resize", position);
      observer.disconnect();
    };
  }, [triggerRef]);

  useEffect(() => {
    const handleMouseDown = (event: MouseEvent) => {
      const target = event.target as Node;
      if (menuRef.current?.contains(target)) return;
      if (triggerRef.current?.contains(target)) return;
      onClose();
    };
    document.addEventListener("mousedown", handleMouseDown);
    return () => document.removeEventListener("mousedown", handleMouseDown);
  }, [onClose, triggerRef]);

  return createPortal(
    <div
      ref={menuRef}
      style={style}
      className={cn(
        "z-[100] rounded-lg border border-border bg-card p-1 shadow-md animate-in fade-in duration-150",
        openUp ? "slide-in-from-bottom-1" : "slide-in-from-top-1",
        className
      )}
    >
      {children}
    </div>,
    document.body
  );
}
