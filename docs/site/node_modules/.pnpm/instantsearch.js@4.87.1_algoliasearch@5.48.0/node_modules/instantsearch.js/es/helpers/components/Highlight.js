var _excluded = ["hit", "attribute", "cssClasses"];
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
function _objectWithoutProperties(e, t) { if (null == e) return {}; var o, r, i = _objectWithoutPropertiesLoose(e, t); if (Object.getOwnPropertySymbols) { var n = Object.getOwnPropertySymbols(e); for (r = 0; r < n.length; r++) o = n[r], -1 === t.indexOf(o) && {}.propertyIsEnumerable.call(e, o) && (i[o] = e[o]); } return i; }
function _objectWithoutPropertiesLoose(r, e) { if (null == r) return {}; var t = {}; for (var n in r) if ({}.hasOwnProperty.call(r, n)) { if (-1 !== e.indexOf(n)) continue; t[n] = r[n]; } return t; }
import { h } from 'preact';
import { Highlight as HighlightUiComponent } from "../../components/Highlight/Highlight.js";
import { getPropertyByPath, unescape, toArray, warning, getHighlightedParts } from "../../lib/utils/index.js";
export function Highlight(_ref) {
  var hit = _ref.hit,
    attribute = _ref.attribute,
    cssClasses = _ref.cssClasses,
    props = _objectWithoutProperties(_ref, _excluded);
  var property = getPropertyByPath(hit._highlightResult, attribute) || [];
  var properties = toArray(property);
  process.env.NODE_ENV === 'development' ? warning(Boolean(properties.length), "Could not enable highlight for \"".concat(attribute.toString(), "\", will display an empty string.\nPlease check whether this attribute exists and is either searchable or specified in `attributesToHighlight`.\n\nSee: https://alg.li/highlighting\n")) : void 0;
  var parts = properties.map(function (_ref2) {
    var value = _ref2.value;
    return getHighlightedParts(unescape(value || ''));
  });
  return h(HighlightUiComponent, _extends({}, props, {
    parts: parts,
    classNames: cssClasses
  }));
}