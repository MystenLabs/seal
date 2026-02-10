"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.useStickToBottom = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _hooks = require("preact/hooks");
/* !---------------------------------------------------------------------------------------------
 *  Copyright (c) StackBlitz. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

var useStickToBottom = exports.useStickToBottom = (0, _instantsearchUiComponents.createStickToBottom)({
  useCallback: _hooks.useCallback,
  useEffect: _hooks.useEffect,
  useMemo: _hooks.useMemo,
  useRef: _hooks.useRef,
  useState: _hooks.useState
});