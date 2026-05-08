/*
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
*/

// @ts-check
// `@type` JSDoc annotations allow editor autocompletion and type checking
// (when paired with `@ts-check`).
// There are various equivalent ways to declare your Docusaurus config.
// See: https://docusaurus.io/docs/api/docusaurus-config

import {themes as prismThemes} from 'prism-react-renderer';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Seal Documentation',
  tagline: 'This is a Walrus Site for Seal documentation.',
  favicon: 'img/favicon.ico',
  headTags: [
    {
      tagName: "meta",
      attributes: {
        name: "algolia-site-verification",
        content: "BCA21DA2879818D2",
      },
    },
  ],
  // Future flags, see https://docusaurus.io/docs/api/docusaurus-config#future
  future: {
    v4: true, // Improve compatibility with the upcoming Docusaurus v4
  },

  url: process.env.DOCUSAURUS_BASE_URL ? 'https://MystenLabs.github.io' : 'https://seal-docs.wal.app',
  baseUrl: process.env.DOCUSAURUS_BASE_URL || '/',
  
  organizationName: 'Mysten Labs',
  projectName: 'seal',

  onBrokenLinks: 'throw',
  onBrokenAnchors: 'warn',
  onBrokenMarkdownLinks: 'warn',
  
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },
  
  markdown: {
    format: "detect",
    mermaid: true,
  },

  scripts: [
    {
      src: "https://widget.kapa.ai/kapa-widget.bundle.js",
      "data-website-id": "91d6cd50-0276-4125-b8c1-3fe897e8fe47",
      "data-project-name": "Seal Knowledge",
      "data-project-color": "#92a4ff",
      "data-button-hide": "true",
      "data-modal-title": "Ask Seal AI",
      "data-modal-ask-ai-input-placeholder": "Ask me anything about Seal!",
      "data-modal-example-questions":
        "How do I encrypt data with Seal?,What is threshold encryption?,How do I create an access policy?,What are key servers?",
      "data-modal-body-bg-color": "#E0E2E6",
      "data-source-link-bg-color": "#FFFFFF",
      "data-source-link-border": "#92a4ff",
      "data-answer-feedback-button-bg-color": "#FFFFFF",
      "data-answer-copy-button-bg-color": "#FFFFFF",
      "data-thread-clear-button-bg-color": "#FFFFFF",
      "data-modal-image": "/img/logo.svg",
      "data-mcp-enabled": "true",
      "data-mcp-server-url": "https://sui.mcp.kapa.ai",
      "data-mcp-button-text": "Use Seal MCP Server",
      async: true,
    },
  ],

  clientModules: [
    require.resolve("./src/client/pushfeedback-toc.js"),
    require.resolve("./src/client/kapa-navbar.js"),
  ],
  
  plugins: [
    function markdownHeadersPlugin() {
      return {
        name: 'markdown-headers-plugin',
        configureWebpack() {
          return {
            devServer: {
              headers: {
                '*.md': {
                  'Content-Type': 'text/markdown; charset=utf-8',
                  'Content-Disposition': 'inline',
                },
                '*.txt': {
                  'Content-Type': 'text/plain; charset=utf-8',
                  'Content-Disposition': 'inline',
                },
              },
              setupMiddlewares(middlewares) {
                middlewares.unshift({
                  name: 'markdown-content-type',
                  middleware: (req, res, next) => {
                    if (req.url.endsWith('.md')) {
                      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
                      res.setHeader('Content-Disposition', 'inline');
                    } else if (req.url.endsWith('.txt')) {
                      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
                      res.setHeader('Content-Disposition', 'inline');
                    }
                    next();
                  },
                });
                return middlewares;
              },
            },
          };
        },
      };
    },
    //require.resolve('./src/plugins/framework'),
    "docusaurus-plugin-copy-page-button",
    [
    "docusaurus-plugin-plausible",
      {
        domain: 'seal-docs.wal.app',
      },
    ],
  ],
  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          path: '../content',
          routeBasePath: '/',
          sidebarPath: './sidebars.js',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      colorMode: {
        respectPrefersColorScheme: true,
      },
      navbar: {
        logo: {
          alt: 'Seal Logo',
          src: 'img/logo.svg',
          href: '/',
        },
        items: [
          {
            href: 'https://github.com/MystenLabs/seal',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
      },
    }),
};

export default config;
