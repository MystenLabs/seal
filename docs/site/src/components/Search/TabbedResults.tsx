// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import React from "react";

export default function TabbedResults({
  activeTab,
  onChange,
  tabs,
  showTooltips = true,
}) {
  return (
    <div
      style={{
        marginBottom: "1rem",
        display: "flex",
        justifyContent: "flex-start",
        borderBottom: "2px solid var(--ifm-color-emphasis-200)",
        gap: "0",
      }}
    >
      {tabs.map(({ label, indexName, count }) => {
        const isActive = activeTab === indexName;
        return (
          <button
            key={indexName}
            onClick={() => onChange(indexName)}
            style={{
              marginRight: "1rem",
              display: "flex",
              alignItems: "center",
              fontWeight: isActive ? 700 : 600,
              fontSize: "0.95rem",
              background: "transparent",
              cursor: "pointer",
              color: isActive
                ? "var(--ifm-font-color-base)"
                : "var(--ifm-color-emphasis-600)",
              border: "none",
              borderBottom: isActive
                ? "2px solid var(--ifm-color-primary)"
                : "2px solid transparent",
              paddingBottom: "0.5rem",
              paddingTop: "0.5rem",
              paddingLeft: "0.25rem",
              paddingRight: "0.25rem",
              marginBottom: "-2px",
              transition: "color 0.15s, border-color 0.15s",
            }}
          >
            {label}{" "}
            <span
              style={{
                fontSize: "0.75rem",
                borderRadius: "9999px",
                marginLeft: "0.35rem",
                padding: "0.15rem 0.5rem",
                border: isActive
                  ? "1px solid var(--ifm-color-emphasis-400)"
                  : "1px solid transparent",
                backgroundColor: isActive
                  ? "transparent"
                  : "var(--ifm-color-emphasis-200)",
                color: isActive
                  ? "var(--ifm-font-color-base)"
                  : "var(--ifm-color-emphasis-600)",
              }}
            >
              {count}
            </span>
          </button>
        );
      })}
    </div>
  );
}
