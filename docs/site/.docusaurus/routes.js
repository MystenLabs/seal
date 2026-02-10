import React from 'react';
import ComponentCreator from '@docusaurus/ComponentCreator';

export default [
  {
    path: '/',
    component: ComponentCreator('/', 'cae'),
    routes: [
      {
        path: '/',
        component: ComponentCreator('/', '87a'),
        routes: [
          {
            path: '/',
            component: ComponentCreator('/', 'c04'),
            routes: [
              {
                path: '/Aggregator',
                component: ComponentCreator('/Aggregator', 'd35'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/Design',
                component: ComponentCreator('/Design', 'f06'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/ExamplePatterns',
                component: ComponentCreator('/ExamplePatterns', 'dd2'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/GettingStarted',
                component: ComponentCreator('/GettingStarted', '791'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/KeyServerCommitteeOps',
                component: ComponentCreator('/KeyServerCommitteeOps', 'f85'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/KeyServerOps',
                component: ComponentCreator('/KeyServerOps', '586'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/Pricing',
                component: ComponentCreator('/Pricing', '1df'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/SealCLI',
                component: ComponentCreator('/SealCLI', '5c9'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/SecurityBestPractices',
                component: ComponentCreator('/SecurityBestPractices', '578'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/TermsOfService',
                component: ComponentCreator('/TermsOfService', 'e3e'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/UsingSeal',
                component: ComponentCreator('/UsingSeal', '303'),
                exact: true,
                sidebar: "docsSidebar"
              },
              {
                path: '/',
                component: ComponentCreator('/', '608'),
                exact: true,
                sidebar: "docsSidebar"
              }
            ]
          }
        ]
      }
    ]
  },
  {
    path: '*',
    component: ComponentCreator('*'),
  },
];
