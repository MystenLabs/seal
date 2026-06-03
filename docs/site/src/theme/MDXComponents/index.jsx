/*
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
*/
import React from "react";
import MDXComponentsOriginal from "@theme-original/MDXComponents";
import Tabs from "@theme/Tabs";
import TabItem from "@theme/TabItem";
import CodeBlock from "@theme/CodeBlock";
import DocCardList from "@theme/DocCardList";
import BrowserOnly from "@docusaurus/BrowserOnly";
import AgentPrompt from "@site/src/shared/components/AgentPrompt";
import RelatedLink from "@site/src/shared/components/RelatedLink";
import UnsafeLink from "@site/src/shared/components/UnsafeLink";

export default {
  ...MDXComponentsOriginal,
  Tabs,
  TabItem,
  CodeBlock,
  DocCardList,
  BrowserOnly,
  AgentPrompt,
  RelatedLink,
  UnsafeLink,
};
