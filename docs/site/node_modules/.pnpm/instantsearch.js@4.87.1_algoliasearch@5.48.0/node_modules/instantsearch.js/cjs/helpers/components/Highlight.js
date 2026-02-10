"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.Highlight = Highlight;
var _preact = require("preact");
var _Highlight = require("../../components/Highlight/Highlight");
var _utils = require("../../lib/utils");
var _excluded = ["hit", "attribute", "cssClasses"];
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
function _objectWithoutProperties(e, t) { if (null == e) return {}; var o, r, i = _objectWithoutPropertiesLoose(e, t); if (Object.getOwnPropertySymbols) { var n = Object.getOwnPropertySymbols(e); for (r = 0; r < n.length; r++) o = n[r], -1 === t.indexOf(o) && {}.propertyIsEnumerable.call(e, o) && (i[o] = e[o]); } return i; }
function _objectWithoutPropertiesLoose(r, e) { if (null == r) return {}; var t = {}; for (var n in r) if ({}.hasOwnProperty.call(r, n)) { if (-1 !== e.indexOf(n)) continue; t[n] = r[n]; } return t; }
function Highlight(_ref) {
  var hit = _ref.hit,
    attribute = _ref.attribute,
    cssClasses = _ref.cssClasses,
    props = _objectWithoutProperties(_ref, _excluded);
  var property = (0, _utils.getPropertyByPath)(hit._highlightResult, attribute) || [];
  var properties = (0, _utils.toArray)(property);
  process.env.NODE_ENV === 'development' ? (0, _utils.warning)(Boolean(properties.length), "Could not enable highlight for \"".concat(attribute.toString(), "\", will display an empty string.\nPlease check whether this attribute exists and is either searchable or specified in `attributesToHighlight`.\n\nSee: https://alg.li/highlighting\n")) : void 0;
  var parts = properties.map(function (_ref2) {
    var value = _ref2.value;
    return (0, _utils.getHighlightedParts)((0, _utils.unescape)(value || ''));
  });
  return (0, _preact.h)(_Highlight.Highlight, _extends({}, props, {
    parts: parts,
    classNames: cssClasses
  }));
}