/* !---------------------------------------------------------------------------------------------
 *  Copyright (c) StackBlitz. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { createStickToBottom } from 'instantsearch-ui-components';
import { useCallback, useEffect, useMemo, useRef, useState } from 'preact/hooks';
export var useStickToBottom = createStickToBottom({
  useCallback: useCallback,
  useEffect: useEffect,
  useMemo: useMemo,
  useRef: useRef,
  useState: useState
});