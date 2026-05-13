// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { useHits } from "react-instantsearch";
import { useHistory } from "@docusaurus/router";
import {
  truncateAtWord,
  getDeepestHierarchyLabel,
  getHierarchyBreadcrumbs,
  cleanTooltipText,
} from "./utils";

export default function CustomHitsContent({ name }) {
  const { hits: items } = useHits();
  const history = useHistory();
  const currentHost =
    typeof window !== "undefined" ? window.location.host : "";

  let siteToVisit = "Try your search again with different keywords";
  if (name === "seal_docs") {
    siteToVisit = `${siteToVisit}. If you are unable to find the information you need, try one of the official support channels: <a href="https://github.com/MystenLabs/seal/issues/new/choose" target="_blank">GitHub</a> or <a href="https://discord.gg/Sui" target="_blank">Discord</a>.`;
  } else if (name === "sui_docs") {
    siteToVisit = `${siteToVisit} or visit the official <a href="https://docs.sui.io" target="_blank">Sui Docs</a> site.`;
  } else if (name === "suins_docs") {
    siteToVisit = `${siteToVisit} or visit the official <a href="https://docs.suins.io" target="_blank">SuiNS Docs</a> site.`;
  } else if (name === "move_book") {
    siteToVisit = `${siteToVisit} or visit <a href="https://move-book.com/" target="_blank">The Move Book</a> dedicated site.`;
  } else if (name === "sui_sdks") {
    siteToVisit = `${siteToVisit} or visit the official <a href="https://sdk.mystenlabs.com" target="_blank">Sui SDKs</a> site.`;
  } else if (name === "walrus_docs") {
    siteToVisit = `${siteToVisit} or visit the official <a href="https://docs.wal.app/" target="_blank">Walrus Docs</a> site.`;
  } else {
    siteToVisit = `${siteToVisit}.`;
  }

  if (items.length === 0) {
    return (
      <>
        <p>No results found.</p>
        <p
          dangerouslySetInnerHTML={{
            __html: `${siteToVisit}`,
          }}
        />
      </>
    );
  }

  const grouped = items.reduce(
    (acc, hit) => {
      const key = hit.url_without_anchor;
      if (!acc[key]) acc[key] = [];
      acc[key].push(hit);
      return acc;
    },
    {} as Record<string, typeof items>,
  );

  return (
    <>
      {Object.entries(grouped).map(([key, group], index) => {
        const pageCrumbs = getHierarchyBreadcrumbs(group[0].hierarchy);
        const pageTitle =
          pageCrumbs.length > 0
            ? pageCrumbs[Math.min(1, pageCrumbs.length - 1)]
            : "[no title]";

        return (
          <div
            key={index}
            style={{
              padding: "1.5rem",
              paddingBottom: "1.5rem",
              marginBottom: "1.5rem",
              backgroundColor: "var(--ifm-color-emphasis-100)",
              borderRadius: "16px",
            }}
          >
            <div
              style={{
                fontSize: "1.125rem",
                fontWeight: 600,
                marginBottom: "0.25rem",
                color: "var(--ifm-font-color-base)",
              }}
            >
              {pageTitle}
            </div>
            {pageCrumbs.length > 0 && (
              <div
                style={{
                  fontSize: "0.75rem",
                  color: "var(--ifm-color-emphasis-600)",
                  marginBottom: "1rem",
                }}
              >
                {pageCrumbs.join(" > ")}
              </div>
            )}
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              {group.map((hit, i) => {
                const hitCrumbs = getHierarchyBreadcrumbs(hit.hierarchy);
                const sectionTitle =
                  hitCrumbs.length > 0
                    ? hitCrumbs[hitCrumbs.length - 1]
                    : cleanTooltipText(
                        getDeepestHierarchyLabel(hit.hierarchy),
                      );

                const hitHost = new URL(hit.url).host;
                const isInternal = hitHost === currentHost;

                return (
                  <div key={i} style={{ padding: "0.25rem 0" }}>
                    {isInternal ? (
                      <button
                        onClick={() =>
                          history.push(new URL(hit.url).pathname)
                        }
                        style={{
                          fontSize: "0.875rem",
                          color: "var(--ifm-color-primary)",
                          fontWeight: 500,
                          textDecoration: "underline",
                          textAlign: "left",
                          background: "transparent",
                          border: 0,
                          padding: 0,
                          cursor: "pointer",
                        }}
                      >
                        {sectionTitle}
                      </button>
                    ) : (
                      <a
                        href={hit.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{
                          fontSize: "0.875rem",
                          color: "var(--ifm-color-primary)",
                          fontWeight: 500,
                          textDecoration: "underline",
                        }}
                      >
                        {sectionTitle}
                      </a>
                    )}
                    {hit.content && (
                      <p
                        style={{
                          fontWeight: 400,
                          fontSize: "0.875rem",
                          color: "var(--ifm-color-emphasis-600)",
                          marginTop: "0.25rem",
                          marginBottom: 0,
                        }}
                        dangerouslySetInnerHTML={{
                          __html: truncateAtWord(
                            hit._highlightResult.content.value,
                          ),
                        }}
                      />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </>
  );
}
