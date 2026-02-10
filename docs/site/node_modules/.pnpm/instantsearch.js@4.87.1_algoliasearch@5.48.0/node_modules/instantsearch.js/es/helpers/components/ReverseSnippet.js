function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
var _excluded = ["hit", "attribute", "cssClasses"],
  _excluded2 = ["isHighlighted"];
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _objectWithoutProperties(e, t) { if (null == e) return {}; var o, r, i = _objectWithoutPropertiesLoose(e, t); if (Object.getOwnPropertySymbols) { var n = Object.getOwnPropertySymbols(e); for (r = 0; r < n.length; r++) o = n[r], -1 === t.indexOf(o) && {}.propertyIsEnumerable.call(e, o) && (i[o] = e[o]); } return i; }
function _objectWithoutPropertiesLoose(r, e) { if (null == r) return {}; var t = {}; for (var n in r) if ({}.hasOwnProperty.call(r, n)) { if (-1 !== e.indexOf(n)) continue; t[n] = r[n]; } return t; }
import { h } from 'preact';
import { ReverseSnippet as ReverseSnippetUiComponent } from "../../components/ReverseSnippet/ReverseSnippet.js";
import { getPropertyByPath, unescape, toArray, warning, getHighlightedParts } from "../../lib/utils/index.js";
export function ReverseSnippet(_ref) {
  var hit = _ref.hit,
    attribute = _ref.attribute,
    cssClasses = _ref.cssClasses,
    props = _objectWithoutProperties(_ref, _excluded);
  var property = getPropertyByPath(hit._snippetResult, attribute) || [];
  var properties = toArray(property);
  process.env.NODE_ENV === 'development' ? warning(Boolean(properties.length), "Could not enable snippet for \"".concat(attribute.toString(), "\", will display an empty string.\nPlease check whether this attribute exists and is specified in `attributesToSnippet`.\n\nSee: https://alg.li/highlighting\n")) : void 0;
  var parts = properties.map(function (_ref2) {
    var value = _ref2.value;
    return getHighlightedParts(unescape(value || '')).map(function (_ref3) {
      var isHighlighted = _ref3.isHighlighted,
        rest = _objectWithoutProperties(_ref3, _excluded2);
      return _objectSpread(_objectSpread({}, rest), {}, {
        isHighlighted: !isHighlighted
      });
    });
  });
  return h(ReverseSnippetUiComponent, _extends({}, props, {
    parts: parts,
    classNames: cssClasses
  }));
}