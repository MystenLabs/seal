"use strict";

function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
Object.defineProperty(exports, "__esModule", {
  value: true
});
var _exportNames = {
  highlight: true,
  reverseHighlight: true,
  snippet: true,
  reverseSnippet: true,
  insights: true,
  getInsightsAnonymousUserToken: true,
  getInsightsAnonymousUserTokenInternal: true
};
Object.defineProperty(exports, "getInsightsAnonymousUserToken", {
  enumerable: true,
  get: function get() {
    return _getInsightsAnonymousUserToken.default;
  }
});
Object.defineProperty(exports, "getInsightsAnonymousUserTokenInternal", {
  enumerable: true,
  get: function get() {
    return _getInsightsAnonymousUserToken.getInsightsAnonymousUserTokenInternal;
  }
});
Object.defineProperty(exports, "highlight", {
  enumerable: true,
  get: function get() {
    return _highlight.default;
  }
});
Object.defineProperty(exports, "insights", {
  enumerable: true,
  get: function get() {
    return _insights.default;
  }
});
Object.defineProperty(exports, "reverseHighlight", {
  enumerable: true,
  get: function get() {
    return _reverseHighlight.default;
  }
});
Object.defineProperty(exports, "reverseSnippet", {
  enumerable: true,
  get: function get() {
    return _reverseSnippet.default;
  }
});
Object.defineProperty(exports, "snippet", {
  enumerable: true,
  get: function get() {
    return _snippet.default;
  }
});
var _highlight = _interopRequireWildcard(require("./highlight"));
Object.keys(_highlight).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (Object.prototype.hasOwnProperty.call(_exportNames, key)) return;
  if (key in exports && exports[key] === _highlight[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function get() {
      return _highlight[key];
    }
  });
});
var _reverseHighlight = _interopRequireWildcard(require("./reverseHighlight"));
Object.keys(_reverseHighlight).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (Object.prototype.hasOwnProperty.call(_exportNames, key)) return;
  if (key in exports && exports[key] === _reverseHighlight[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function get() {
      return _reverseHighlight[key];
    }
  });
});
var _snippet = _interopRequireWildcard(require("./snippet"));
Object.keys(_snippet).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (Object.prototype.hasOwnProperty.call(_exportNames, key)) return;
  if (key in exports && exports[key] === _snippet[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function get() {
      return _snippet[key];
    }
  });
});
var _reverseSnippet = _interopRequireWildcard(require("./reverseSnippet"));
Object.keys(_reverseSnippet).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (Object.prototype.hasOwnProperty.call(_exportNames, key)) return;
  if (key in exports && exports[key] === _reverseSnippet[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function get() {
      return _reverseSnippet[key];
    }
  });
});
var _insights = _interopRequireDefault(require("./insights"));
var _getInsightsAnonymousUserToken = _interopRequireWildcard(require("./get-insights-anonymous-user-token"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _interopRequireWildcard(e, t) { if ("function" == typeof WeakMap) var r = new WeakMap(), n = new WeakMap(); return (_interopRequireWildcard = function _interopRequireWildcard(e, t) { if (!t && e && e.__esModule) return e; var o, i, f = { __proto__: null, default: e }; if (null === e || "object" != _typeof(e) && "function" != typeof e) return f; if (o = t ? n : r) { if (o.has(e)) return o.get(e); o.set(e, f); } for (var _t in e) "default" !== _t && {}.hasOwnProperty.call(e, _t) && ((i = (o = Object.defineProperty) && Object.getOwnPropertyDescriptor(e, _t)) && (i.get || i.set) ? o(f, _t, i) : f[_t] = e[_t]); return f; })(e, t); }