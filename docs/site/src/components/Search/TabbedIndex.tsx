// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { Index } from "react-instantsearch";
import VirtualSearchBox from "./VirtualSearchBox";
import RefinementSection from "./RefinementSection";
import ConditionalPagination from "./ConditionalPagination";
import CustomHitsContent from "./CustomHitsContent";

export default function TabbedIndex({
  indexName,
  query,
}: {
  indexName: string;
  query: string;
}) {
  return (
    <Index indexName={indexName}>
      <VirtualSearchBox query={query} />
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(12, 1fr)",
          gap: "1rem",
        }}
      >
        <RefinementSection />
        <div style={{ gridColumn: "span 9" }}>
          <CustomHitsContent name={indexName} />
        </div>
        <div style={{ gridColumn: "span 12" }}>
          <ConditionalPagination />
        </div>
      </div>
    </Index>
  );
}
