import { Check, ChevronDown } from "lucide-react";
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

export interface DropdownOption {
  value: string;
  label: string;
  sub?: string;
}

export interface DropdownProps {
  value: string;
  options: DropdownOption[];
  onChange: (value: string) => void;
  variant?: "type" | "model";
  "aria-label"?: string;
}

interface MenuPosition {
  top: number;
  left: number;
  width: number;
  openUp: boolean;
}

function useMenuPosition(
  triggerRef: React.RefObject<HTMLButtonElement | null>,
  open: boolean,
  menuWidth: number,
): MenuPosition {
  const [pos, setPos] = useState<MenuPosition>({
    top: 0,
    left: 0,
    width: menuWidth,
    openUp: false,
  });

  useLayoutEffect(() => {
    if (!open || !triggerRef.current) return;
    const r = triggerRef.current.getBoundingClientRect();
    const spaceBelow = window.innerHeight - r.bottom;
    const spaceAbove = r.top;
    const openUp = spaceBelow < 200 && spaceAbove > spaceBelow;
    const width = Math.max(r.width, menuWidth);

    setPos({
      top: openUp ? r.top + window.scrollY - 8 : r.bottom + window.scrollY + 6,
      left: r.left + window.scrollX,
      width,
      openUp,
    });
  }, [open, triggerRef, menuWidth]);

  return pos;
}

// ── Shared Menu Portal ───────────────────────────────────────────────────────

interface MenuPortalProps {
  pos: MenuPosition;
  align?: "left" | "right";
  children: React.ReactNode;
  extraClass?: string;
}

function MenuPortal({ pos, align = "left", children, extraClass = "" }: MenuPortalProps) {
  const style: React.CSSProperties = {
    position: "absolute",
    top: pos.openUp ? undefined : pos.top,
    bottom: pos.openUp ? window.innerHeight - pos.top : undefined,
    left: align === "left" ? pos.left : undefined,
    right: align === "right" ? window.innerWidth - pos.left - pos.width : undefined,
    minWidth: pos.width,
    zIndex: 9999,
  };

  return createPortal(
    <div className={`dd-menu ${extraClass}`} style={style} role="listbox">
      {children}
    </div>,
    document.body,
  );
}

// ── Dropdown ─────────────────────────────────────────────────────────────────

export default function Dropdown({
  value,
  options,
  onChange,
  variant = "type",
  "aria-label": ariaLabel,
}: DropdownProps) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const selected = options.find((o) => o.value === value) ?? options[0];
  const menuWidth = variant === "type" ? 230 : 140;
  const pos = useMenuPosition(triggerRef, open, menuWidth);

  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      if (
        triggerRef.current &&
        !triggerRef.current.contains(e.target as Node) &&
        !(e.target as Element).closest(".dd-menu")
      )
        setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const selectOption = (val: string) => {
    onChange(val);
    setOpen(false);
  };

  const menuItems = options.map((opt) => (
    <button
      key={opt.value}
      type="button"
      role="option"
      aria-selected={opt.value === value}
      className={`dd-item ${opt.value === value ? "dd-item--active" : ""}`}
      onMouseDown={(e) => e.preventDefault()}
      onClick={() => selectOption(opt.value)}
    >
      <span>
        <span className="dd-item-label">{opt.label}</span>
        {opt.sub && <span className="dd-item-sub">{opt.sub}</span>}
      </span>
      {opt.value === value && <Check size={13} className="dd-item-check" />}
    </button>
  ));

  if (variant === "model") {
    return (
      <div className="dd-model-root">
        <button
          ref={triggerRef}
          type="button"
          className={`dd-model-trigger ${open ? "dd-model-trigger--open" : ""}`}
          onClick={() => setOpen((v) => !v)}
          aria-haspopup="listbox"
          aria-expanded={open}
          aria-label={ariaLabel}
        >
          <span className="dd-model-prefix">Model:</span>
          <span className="dd-model-value">{selected.label}</span>
          <ChevronDown
            size={12}
            className={`dd-chevron ${open ? "dd-chevron--open" : ""}`}
          />
        </button>
        {open && (
          <MenuPortal pos={pos} align="right" extraClass="dd-menu--model">
            {menuItems}
          </MenuPortal>
        )}
      </div>
    );
  }

  return (
    <div className="dd-type-root">
      <button
        ref={triggerRef}
        type="button"
        className={`dd-type-trigger ${open ? "dd-type-trigger--open" : ""}`}
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={ariaLabel}
      >
        <span className="dd-type-value">{selected.label}</span>
        <ChevronDown
          size={13}
          className={`dd-chevron ${open ? "dd-chevron--open" : ""}`}
        />
      </button>
      {open && (
        <MenuPortal pos={pos} align="left" extraClass="dd-menu--type">
          {menuItems}
        </MenuPortal>
      )}
    </div>
  );
}
