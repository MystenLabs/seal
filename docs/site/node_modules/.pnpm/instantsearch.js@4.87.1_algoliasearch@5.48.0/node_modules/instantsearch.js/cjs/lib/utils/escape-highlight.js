"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.TAG_REPLACEMENT = exports.TAG_PLACEHOLDER = void 0;
exports.escapeFacets = escapeFacets;
exports.escapeHits = escapeHits;
var _escapeHtml = require("./escape-html");
var _isPlainObject = require("./isPlainObject");
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function _objectDestructuringEmpty(t) { if (null == t) throw new TypeError("Cannot destructure " + t); }
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
var TAG_PLACEHOLDER = exports.TAG_PLACEHOLDER = {
  highlightPreTag: '__ais-highlight__',
  highlightPostTag: '__/ais-highlight__'
};
var TAG_REPLACEMENT = exports.TAG_REPLACEMENT = {
  highlightPreTag: '<mark>',
  highlightPostTag: '</mark>'
};

// @MAJOR: in the future, this should only escape, not replace
function replaceTagsAndEscape(value) {
  return (0, _escapeHtml.escape)(value).replace(new RegExp(TAG_PLACEHOLDER.highlightPreTag, 'g'), TAG_REPLACEMENT.highlightPreTag).replace(new RegExp(TAG_PLACEHOLDER.highlightPostTag, 'g'), TAG_REPLACEMENT.highlightPostTag);
}
function recursiveEscape(input) {
  if ((0, _isPlainObject.isPlainObject)(input) && typeof input.value !== 'string') {
    return Object.keys(input).reduce(function (acc, key) {
      return _objectSpread(_objectSpread({}, acc), {}, _defineProperty({}, key, recursiveEscape(input[key])));
    }, {});
  }
  if (Array.isArray(input)) {
    return input.map(recursiveEscape);
  }
  return _objectSpread(_objectSpread({}, input), {}, {
    value: replaceTagsAndEscape(input.value)
  });
}
function escapeHits(hits) {
  if (hits.__escaped === undefined) {
    // We don't override the value on hit because it will mutate the raw results
    // instead we make a shallow copy and we assign the escaped values on it.
    hits = hits.map(function (_ref) {
      var hit = _extends({}, (_objectDestructuringEmpty(_ref), _ref));
      if (hit._highlightResult) {
        hit._highlightResult = recursiveEscape(hit._highlightResult);
      }
      if (hit._snippetResult) {
        hit._snippetResult = recursiveEscape(hit._snippetResult);
      }
      return hit;
    });
    hits.__escaped = true;
  }
  return hits;
}
function escapeFacets(facetHits) {
  return facetHits.map(function (h) {
    return _objectSpread(_objectSpread({}, h), {}, {
      highlighted: replaceTagsAndEscape(h.highlighted)
    });
  });
}