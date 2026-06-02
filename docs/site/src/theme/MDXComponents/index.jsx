/*
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
*/
import React from "react";
import MDXComponentsOriginal from "@theme-original/MDXComponents";
import Tabs from "@theme/Tabs";
import TabItem from "@theme/TabItem";
import { Card, Cards } from "@site/src/shared/components/Cards";
import CodeBlock from "@theme/CodeBlock";
import DocCardList from "@theme/DocCardList";
import BrowserOnly from "@docusaurus/BrowserOnly";
import UnsafeLink from "@site/src/shared/components/UnsafeLink";
import RelatedLink from "@site/src/shared/components/RelatedLink";
import ImportContent from "@site/src/shared/components/ImportContent";
import AgentPrompt from "@site/src/shared/components/AgentPrompt";
import Term from "@site/src/shared/components/Glossary/Term";

export default {
  ...MDXComponentsOriginal,
  Card,
  Cards,
  Tabs,
  TabItem,
  CodeBlock,
  DocCardList,
  BrowserOnly,
  UnsafeLink,
  RelatedLink,
  ImportContent,
  AgentPrompt,
  Term,
};
