// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { useHits, usePagination } from "react-instantsearch";

const step = (
  <svg
    width="12"
    height="18"
    viewBox="0 0 12 12"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
  >
    <path
      d="M2.47885 0.806646L10.3905 5.1221C11.0854 5.50112 11.0854 6.49888 10.3905 6.8779L2.47885 11.1934C1.81248 11.5568 1 11.0745 1 10.3155V1.68454C1 0.925483 1.81248 0.443169 2.47885 0.806646Z"
      stroke="#A0B6C3"
    />
  </svg>
);

const jump = (
  <svg
    width="20"
    height="18"
    viewBox="0 0 20 12"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
  >
    <path
      d="M2.47885 0.806646L10.3905 5.1221C11.0854 5.50112 11.0854 6.49888 10.3905 6.8779L2.47885 11.1934C1.81248 11.5568 1 11.0745 1 10.3155V1.68454C1 0.925483 1.81248 0.443169 2.47885 0.806646Z"
      fill="white"
      fillOpacity="0.8"
      stroke="#A0B6C3"
    />
    <path
      d="M10.4789 0.806646L18.3905 5.1221C19.0854 5.50112 19.0854 6.49888 18.3905 6.8779L10.4789 11.1934C9.81248 11.5568 9 11.0745 9 10.3155V1.68454C9 0.925483 9.81248 0.443169 10.4789 0.806646Z"
      fill="white"
      fillOpacity="0.8"
      stroke="#A0B6C3"
    />
  </svg>
);

const pageItemBase = {
  padding: "0.5rem 0.75rem",
  border: "1px solid var(--ifm-color-emphasis-300)",
  borderRadius: "6px",
  fontSize: "0.875rem",
  cursor: "pointer",
  color: "var(--ifm-font-color-base)",
  background: "transparent",
  display: "flex",
  alignItems: "center",
};

const disabledStyle = {
  ...pageItemBase,
  opacity: 0.5,
  cursor: "not-allowed",
};

function CustomPagination() {
  const { currentRefinement, nbPages, refine, pages } = usePagination();

  if (nbPages <= 1) return null;

  return (
    <ul
      style={{
        display: "flex",
        gap: "0.5rem",
        marginTop: "1rem",
        justifyContent: "center",
        alignItems: "center",
        listStyle: "none",
        padding: 0,
      }}
    >
      {nbPages > 2 && (
        <li
          onClick={() => refine(0)}
          style={currentRefinement === 0 ? disabledStyle : pageItemBase}
        >
          <div
            style={{
              transform: "rotate(180deg)",
              display: "flex",
              alignItems: "center",
            }}
          >
            {jump}
          </div>
        </li>
      )}
      {nbPages > 1 && (
        <li
          onClick={() =>
            currentRefinement > 0 && refine(currentRefinement - 1)
          }
          style={currentRefinement === 0 ? disabledStyle : pageItemBase}
        >
          <div
            style={{
              transform: "rotate(180deg)",
              display: "flex",
              alignItems: "center",
            }}
          >
            {step}
          </div>
        </li>
      )}
      {pages.map((page) => {
        const isActive = currentRefinement === page;
        return (
          <li
            key={page}
            onClick={() => refine(page)}
            style={{
              ...pageItemBase,
              backgroundColor: isActive
                ? "rgba(146, 164, 255, 0.25)"
                : "transparent",
              fontWeight: isActive ? 700 : 400,
            }}
          >
            {page + 1}
          </li>
        );
      })}
      {nbPages > 1 && (
        <li
          onClick={() =>
            currentRefinement < nbPages - 1 &&
            refine(currentRefinement + 1)
          }
          style={
            currentRefinement === nbPages - 1
              ? disabledStyle
              : pageItemBase
          }
        >
          <div style={{ display: "flex", alignItems: "center" }}>{step}</div>
        </li>
      )}
      {nbPages > 2 && (
        <li
          onClick={() => refine(nbPages - 1)}
          style={
            currentRefinement === nbPages - 1
              ? disabledStyle
              : pageItemBase
          }
        >
          <div style={{ display: "flex", alignItems: "center" }}>{jump}</div>
        </li>
      )}
    </ul>
  );
}

export default function ConditionalPagination() {
  const { hits } = useHits();
  if (hits.length === 0) return null;
  return <CustomPagination />;
}
