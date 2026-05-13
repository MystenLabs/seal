// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import React, { useState, useEffect } from "react";
import { liteClient as algoliasearch } from "algoliasearch/lite";
import {
  InstantSearch,
  useInfiniteHits,
  useInstantSearch,
  Index,
} from "react-instantsearch";
import {
  truncateAtWord,
  getHierarchyBreadcrumbs,
  cleanTooltipText,
} from "./utils";
import ControlledSearchBox from "./ControlledSearchBox";
import TabbedResults from "./TabbedResults";

const baseSearchClient = algoliasearch(
  "M9JD2UP87M",
  "826134b026a63bb35692f08f1dc85d1c",
);

const searchClient = {
  ...baseSearchClient,
  search(requests: any[]) {
    const hasValidQuery = requests.some(
      (req) => req.params?.query?.length >= 3,
    );
    if (!hasValidQuery) {
      return Promise.resolve({
        results: requests.map(() => ({
          hits: [],
          nbHits: 0,
          processingTimeMS: 0,
        })),
      });
    }
    return baseSearchClient.search(requests);
  },
};

const indices = [
  { label: "Seal", indexName: "seal_docs" },
  { label: "Sui", indexName: "sui_docs" },
  { label: "SuiNS", indexName: "suins_docs" },
  { label: "The Move Book", indexName: "move_book" },
  { label: "SDKs", indexName: "sui_sdks" },
  { label: "Walrus", indexName: "walrus_docs" },
];

function HitItem({ hit }: { hit: any }) {
  const crumbs = getHierarchyBreadcrumbs(hit.hierarchy);
  const title =
    crumbs.length > 0
      ? crumbs[crumbs.length - 1]
      : cleanTooltipText(hit.hierarchy?.lvl0 || "Untitled");
  const breadcrumb = crumbs.length > 1 ? crumbs.slice(0, -1) : [];

  return (
    <a
      href={hit.url}
      className="modal-result"
      style={{
        display: "block",
        padding: "0.75rem 1rem",
        margin: "0 -0.5rem",
        borderRadius: "8px",
        textDecoration: "none",
        color: "inherit",
        transition: "background-color 0.15s",
      }}
      onMouseEnter={(e) =>
        (e.currentTarget.style.backgroundColor =
          "var(--ifm-color-emphasis-100)")
      }
      onMouseLeave={(e) =>
        (e.currentTarget.style.backgroundColor = "transparent")
      }
    >
      {breadcrumb.length > 0 && (
        <div
          style={{
            fontSize: "0.75rem",
            color: "var(--ifm-color-emphasis-600)",
            marginBottom: "0.25rem",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {breadcrumb.join(" > ")}
        </div>
      )}
      <div
        style={{
          fontSize: "0.875rem",
          fontWeight: 500,
          color: "var(--ifm-font-color-base)",
        }}
      >
        {title}
      </div>
      {hit.content && (
        <p
          style={{
            fontSize: "0.75rem",
            color: "var(--ifm-color-emphasis-600)",
            marginTop: "0.25rem",
            marginBottom: 0,
            display: "-webkit-box",
            WebkitLineClamp: 2,
            WebkitBoxOrient: "vertical",
            overflow: "hidden",
          }}
          dangerouslySetInnerHTML={{
            __html: truncateAtWord(hit._highlightResult.content.value, 120),
          }}
        />
      )}
    </a>
  );
}

function HitsList({
  scrollContainerRef,
}: {
  scrollContainerRef: React.RefObject<HTMLDivElement>;
}) {
  const { hits, isLastPage, showMore } = useInfiniteHits();

  useEffect(() => {
    const el = scrollContainerRef.current;
    if (!el) return;

    const handleScroll = () => {
      const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 1;
      if (atBottom && !isLastPage) {
        showMore();
      }
    };

    el.addEventListener("scroll", handleScroll);
    return () => el.removeEventListener("scroll", handleScroll);
  }, [isLastPage, showMore, scrollContainerRef]);

  return (
    <div>
      {hits.map((hit) => (
        <HitItem key={hit.objectID} hit={hit} />
      ))}
    </div>
  );
}

function EmptyState({ label }: { label: string }) {
  const { results } = useInstantSearch();
  if (results?.hits?.length === 0) {
    return (
      <p style={{ fontSize: "0.875rem", color: "var(--ifm-color-emphasis-600)" }}>
        No results in {label}
      </p>
    );
  }
  return null;
}

function ResultsUpdater({
  indexName,
  onUpdate,
}: {
  indexName: string;
  onUpdate: (index: string, count: number) => void;
}) {
  const { results } = useInstantSearch();
  const previousHitsRef = React.useRef<number | null>(null);
  useEffect(() => {
    if (results && results.nbHits !== previousHitsRef.current) {
      previousHitsRef.current = results.nbHits;
      onUpdate(indexName, results.nbHits);
    }
  }, [results?.nbHits, indexName, onUpdate, results]);
  return null;
}

export default function MultiIndexSearchModal({
  isOpen,
  onClose,
}: {
  isOpen: boolean;
  onClose: () => void;
}) {
  const [activeIndex, setActiveIndex] = useState(indices[0].indexName);
  const [tabCounts, setTabCounts] = React.useState<Record<string, number>>({
    seal_docs: 0,
  });
  const [query, setQuery] = React.useState("");
  const scrollContainerRef = React.useRef<HTMLDivElement>(null);
  const searchBoxRef = React.useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = "hidden";
      setTimeout(() => {
        searchBoxRef.current?.focus();
      }, 300);
    } else {
      document.body.style.overflow = "";
    }
    return () => {
      document.body.style.overflow = "";
    };
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  const activeMeta = {
    seal_docs: null,
    sui_docs: { label: "Sui Docs", url: "https://docs.sui.io" },
    suins_docs: { label: "SuiNS Docs", url: "https://docs.suins.io" },
    move_book: {
      label: "The Move Book",
      url: "https://move-book.com/",
    },
    sui_sdks: { label: "SDK Docs", url: "https://sdk.mystenlabs.com" },
    walrus_docs: { label: "Walrus Docs", url: "https://docs.wal.app" },
  }[activeIndex];

  if (!isOpen) return null;

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        backgroundColor: "rgba(0, 0, 0, 0.5)",
        zIndex: 200,
        display: "flex",
        justifyContent: "center",
        alignItems: "flex-start",
        paddingTop: "10vh",
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        style={{
          backgroundColor: "var(--ifm-background-color)",
          width: "100%",
          maxWidth: "56rem",
          borderRadius: "12px",
          boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.25)",
          maxHeight: "min(600px, 80vh)",
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
          margin: "0 1rem",
        }}
      >
        <div
          ref={scrollContainerRef}
          style={{ flex: 1, overflowY: "auto", minHeight: 0 }}
        >
          <InstantSearch searchClient={searchClient} indexName={activeIndex}>
            <div
              style={{
                backgroundColor: "var(--ifm-background-color)",
                borderRadius: "12px 12px 0 0",
                position: "sticky",
                top: 0,
                zIndex: 10,
                padding: "0 1.5rem",
              }}
            >
              <div
                style={{
                  backgroundColor: "var(--ifm-background-color)",
                  height: "2rem",
                  display: "flex",
                  justifyContent: "flex-end",
                }}
              >
                <button
                  onClick={onClose}
                  style={{
                    background: "transparent",
                    border: "none",
                    outline: "none",
                    fontSize: "0.75rem",
                    color: "var(--ifm-color-emphasis-500)",
                    cursor: "pointer",
                  }}
                >
                  ESC
                </button>
              </div>
              <ControlledSearchBox
                placeholder="Search"
                query={query}
                onChange={setQuery}
                inputRef={searchBoxRef}
              />
              {query.length < 3 && (
                <p
                  style={{
                    fontSize: "0.75rem",
                    color: "var(--ifm-color-emphasis-500)",
                    paddingLeft: "0.25rem",
                    marginBottom: "0.5rem",
                    marginTop: "-1.5rem",
                  }}
                >
                  Type at least 3 characters to search
                </p>
              )}
              <TabbedResults
                activeTab={activeIndex}
                onChange={setActiveIndex}
                showTooltips={false}
                tabs={indices.map((tab) => ({
                  ...tab,
                  count: tabCounts[tab.indexName] || 0,
                }))}
              />
            </div>
            <div style={{ padding: "0 1.5rem 1rem" }}>
              {indices.map((index) => (
                <Index indexName={index.indexName} key={index.indexName}>
                  <ResultsUpdater
                    indexName={index.indexName}
                    onUpdate={(indexName, count) =>
                      setTabCounts((prev) => ({
                        ...prev,
                        [indexName]: count,
                      }))
                    }
                  />
                  {index.indexName === activeIndex && (
                    <>
                      <HitsList scrollContainerRef={scrollContainerRef} />
                      <EmptyState label={index.label} />
                    </>
                  )}
                </Index>
              ))}
            </div>
          </InstantSearch>
        </div>
        <div
          style={{
            height: "3rem",
            padding: "0 1.5rem",
            backgroundColor: "var(--ifm-background-color)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            fontSize: "0.75rem",
            borderTop: "1px solid var(--ifm-color-emphasis-200)",
            flexShrink: 0,
          }}
        >
          <a
            href={`/search?q=${encodeURIComponent(query)}`}
            style={{
              color: "var(--ifm-color-emphasis-600)",
              textDecoration: "none",
            }}
          >
            View all results
          </a>
          {activeMeta && (
            <a
              href={activeMeta.url}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                color: "var(--ifm-color-emphasis-600)",
                textDecoration: "none",
              }}
            >
              {activeMeta.label} &rarr;
            </a>
          )}
        </div>
      </div>
    </div>
  );
}
