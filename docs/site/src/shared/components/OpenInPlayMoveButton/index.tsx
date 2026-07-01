// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/**
 * OpenInPlayMoveButton — inline button that opens the current Move code block
 * in PlayMove (https://www.playmove.dev) in a new tab. Designed to sit inside a
 * Docusaurus CodeBlock button bar next to Copy and "Use an Agent".
 *
 * PlayMove reads its editor contents from `window.location.hash`, so opening
 * `https://www.playmove.dev/#<encodeURIComponent(code)>` pre-populates it.
 *
 * The button only renders for Move code blocks. It walks the DOM upward from
 * its own position to find a `pre code[class*='language-move']` element, and
 * extracts the code text the same way as the agent button.
 */
import React, {
  useState,
  useRef,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import clsx from "clsx";
import styles from "./styles.module.css";

/* ---------- helpers ---------- */

/** Walk up from `start` to find the nearest code text in the code block. */
function getNearestCodeText(start: HTMLElement | null): string {
  let el: HTMLElement | null = start;
  while (el) {
    const code = el.querySelector?.(
      "pre code, code, pre",
    ) as HTMLElement | null;
    if (code?.innerText) {
      return code.innerText.replace(/^\$ /gm, "").replace(/\n$/, "");
    }
    el = el.parentElement;
  }
  return "";
}

/** Walk up from `start` to detect whether the code block uses Move. */
function isMoveCodeBlock(start: HTMLElement | null): boolean {
  let el: HTMLElement | null = start;
  while (el) {
    if (el.querySelector?.("pre code[class*='language-move']")) return true;
    el = el.parentElement;
  }
  return false;
}

/* ---------- component ---------- */

export default function OpenInPlayMoveButton({
  className,
  ButtonComponent,
}: {
  className?: string;
  /** Optional base button component from the site's theme (e.g. @theme/CodeBlock/Buttons/Button).
   *  Falls back to a plain <button> when not provided. */
  ButtonComponent?: React.ComponentType<
    React.ButtonHTMLAttributes<HTMLButtonElement>
  >;
}): ReactNode {
  const wrapperRef = useRef<HTMLSpanElement | null>(null);
  const [isMove, setIsMove] = useState(false);

  const Btn = ButtonComponent ?? "button";

  // Detect whether this code block uses the Move language, once on mount.
  useEffect(() => {
    setIsMove(isMoveCodeBlock(wrapperRef.current));
  }, []);

  const handleClick = useCallback(() => {
    const code = getNearestCodeText(wrapperRef.current);
    if (!code) return;
    window.open(
      `https://www.playmove.dev/#${encodeURIComponent(code)}`,
      "_blank",
      "noopener",
    );
  }, []);

  // Always render the wrapper so the ref is set on mount. Toggle visibility
  // via `display` based on whether this is a Move code block.
  return (
    <span
      ref={wrapperRef}
      style={{ display: isMove ? "contents" : "none" }}
    >
      <Btn
        type="button"
        className={clsx(className, styles.triggerBtn, "clean-btn")}
        aria-label="Open in Move Playground"
        title="Open in Move Playground"
        onClick={handleClick}
      >
        <svg
          width="12"
          height="12"
          viewBox="0 0 24 24"
          fill="currentColor"
          xmlns="http://www.w3.org/2000/svg"
        >
          <path d="M8 5v14l11-7z" />
        </svg>
        <span className={styles.label}>Playground</span>
      </Btn>
    </span>
  );
}
