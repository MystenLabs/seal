/*
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
*/

const sidebars = {
  docsSidebar: [
    {
      type: `category`,
      label: `What is Seal?`,
      link: {
        type: `doc`,
        id: `index`,
      },
      collapsed: false,
      items: [
        `ServerOverview`,
      ]
    },
    'GettingStarted',
    'ServerOverview',
    {
      type: 'category',
      label: 'Developer Guide',
      items: [
        'Design',
        'UsingSeal',
        'ExamplePatterns',
        'SecurityBestPractices',
      ],
    },
    {
      type: 'category',
      label: 'Operator Guide',
      items: [
        'KeyServerOps',
        'KeyServerCommitteeOps',
        'Aggregator',
        'SealCLI',
      ],
    },
    'Pricing',
    'TermsOfService',
  ],
};

module.exports = sidebars;