var _excluded = ["classNames"];
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
function _objectWithoutProperties(e, t) { if (null == e) return {}; var o, r, i = _objectWithoutPropertiesLoose(e, t); if (Object.getOwnPropertySymbols) { var n = Object.getOwnPropertySymbols(e); for (r = 0; r < n.length; r++) o = n[r], -1 === t.indexOf(o) && {}.propertyIsEnumerable.call(e, o) && (i[o] = e[o]); } return i; }
function _objectWithoutPropertiesLoose(r, e) { if (null == r) return {}; var t = {}; for (var n in r) if ({}.hasOwnProperty.call(r, n)) { if (-1 !== e.indexOf(n)) continue; t[n] = r[n]; } return t; }
import { cx } from 'instantsearch-ui-components';
import { h } from 'preact';
import { InternalHighlight } from "../InternalHighlight/InternalHighlight.js";
export function Highlight(_ref) {
  var _ref$classNames = _ref.classNames,
    classNames = _ref$classNames === void 0 ? {} : _ref$classNames,
    props = _objectWithoutProperties(_ref, _excluded);
  return h(InternalHighlight, _extends({
    classNames: {
      root: cx('ais-Highlight', classNames.root),
      highlighted: cx('ais-Highlight-highlighted', classNames.highlighted),
      nonHighlighted: cx('ais-Highlight-nonHighlighted', classNames.nonHighlighted),
      separator: cx('ais-Highlight-separator', classNames.separator)
    }
  }, props));
}