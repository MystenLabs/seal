// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// @ts-check

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.

 @type {import('@docusaurus/plugin-content-docs').SidebarsConfig}
 */
const sidebars = {
  docsSidebar: [
    'index',
    'Design',
    'GettingStarted',
    'UsingSeal',
    'ExamplePatterns',
    'SecurityBestPractices',
    'KeyServerOps',
    'KeyServerCommitteeOps',
    'Aggregator',
    'SealCLI',
    'Pricing',
    'TermsOfService',
  ],
};

export default sidebars;
