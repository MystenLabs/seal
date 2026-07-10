// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import React from 'react';
import ReactDOM from 'react-dom/client';
import '@radix-ui/themes/styles.css';

import { DAppKitProvider } from '@mysten/dapp-kit-react';
import { Theme } from '@radix-ui/themes';
import App from './App';
import { dAppKit } from './dapp-kit';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Theme appearance="dark">
      <DAppKitProvider dAppKit={dAppKit}>
        <App />
      </DAppKitProvider>
    </Theme>
  </React.StrictMode>,
);
