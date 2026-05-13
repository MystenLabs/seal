// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { useRefinementList, useHits } from "react-instantsearch";

export default function RefinementSection() {
  const { hits } = useHits();
  const { items, refine } = useRefinementList({ attribute: "source" });

  if (hits.length === 0) return null;

  return (
    <div
      style={{
        gridColumn: "span 3",
      }}
      className="seal-refinement-section"
    >
      <div
        style={{
          position: "sticky",
          marginRight: "1rem",
          padding: "1.5rem",
          paddingBottom: "2.5rem",
          top: "6rem",
          zIndex: 10,
          border: "1px solid var(--ifm-color-emphasis-300)",
          borderRadius: "20px",
        }}
      >
        <h2
          style={{
            fontSize: "1.125rem",
            fontWeight: 600,
            color: "var(--ifm-font-color-base)",
          }}
        >
          Refine results
        </h2>
        <ul style={{ paddingLeft: 0, listStyle: "none" }}>
          {items.map((item) => (
            <li
              key={item.label}
              style={{
                color: "var(--ifm-font-color-base)",
                marginBottom: "0.5rem",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                width: "100%",
              }}
            >
              <label
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.5rem",
                  fontSize: "0.875rem",
                  cursor: "pointer",
                }}
              >
                <input
                  type="checkbox"
                  checked={item.isRefined}
                  onChange={() => refine(item.value)}
                />
                <span
                  style={{
                    fontWeight: item.isRefined ? 700 : 400,
                  }}
                >
                  {item.label}
                </span>
              </label>
              <span
                style={{
                  fontSize: "0.875rem",
                  color: "var(--ifm-color-emphasis-600)",
                }}
              >
                {item.count}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
