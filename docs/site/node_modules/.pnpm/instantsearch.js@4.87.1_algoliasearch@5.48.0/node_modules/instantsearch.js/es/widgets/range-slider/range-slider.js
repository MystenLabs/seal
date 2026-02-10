function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _slicedToArray(r, e) { return _arrayWithHoles(r) || _iterableToArrayLimit(r, e) || _unsupportedIterableToArray(r, e) || _nonIterableRest(); }
function _nonIterableRest() { throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
function _iterableToArrayLimit(r, l) { var t = null == r ? null : "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"]; if (null != t) { var e, n, i, u, a = [], f = !0, o = !1; try { if (i = (t = t.call(r)).next, 0 === l) { if (Object(t) !== t) return; f = !1; } else for (; !(f = (e = i.call(t)).done) && (a.push(e.value), a.length !== l); f = !0); } catch (r) { o = !0, n = r; } finally { try { if (!f && null != t.return && (u = t.return(), Object(u) !== u)) return; } finally { if (o) throw n; } } return a; } }
function _arrayWithHoles(r) { if (Array.isArray(r)) return r; }
import { cx } from 'instantsearch-ui-components';
import { h, render } from 'preact';
import Slider from "../../components/Slider/Slider.js";
import connectRange from "../../connectors/range/connectRange.js";
import { component } from "../../lib/suit.js";
import { getContainerNode, createDocumentationMessageGenerator } from "../../lib/utils/index.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'range-slider'
});
var suit = component('RangeSlider');
var renderer = function renderer(_ref) {
  var containerNode = _ref.containerNode,
    cssClasses = _ref.cssClasses,
    pips = _ref.pips,
    step = _ref.step,
    tooltips = _ref.tooltips;
  return function (_ref2, isFirstRendering) {
    var refine = _ref2.refine,
      range = _ref2.range,
      start = _ref2.start;
    if (isFirstRendering) {
      // There's no information at this point, let's render nothing.
      return;
    }
    var minRange = range.min,
      maxRange = range.max;
    var _start = _slicedToArray(start, 2),
      minStart = _start[0],
      maxStart = _start[1];
    var minFinite = minStart === -Infinity ? minRange : minStart;
    var maxFinite = maxStart === Infinity ? maxRange : maxStart;

    // Clamp values to the range for avoid extra rendering & refinement
    // Should probably be done on the connector side, but we need to stay
    // backward compatible so we still need to pass [-Infinity, Infinity]
    var values = [minFinite > maxRange ? maxRange : minFinite, maxFinite < minRange ? minRange : maxFinite];
    render(h(Slider, {
      cssClasses: cssClasses,
      refine: refine,
      min: minRange,
      max: maxRange,
      values: values,
      tooltips: tooltips,
      step: step,
      pips: pips
    }), containerNode);
  };
};
/**
 * The range slider is a widget which provides a user-friendly way to filter the
 * results based on a single numeric range.
 *
 * @requirements
 * The attribute passed to `attribute` must be declared as an
 * [attribute for faceting](https://www.algolia.com/doc/guides/searching/faceting/#declaring-attributes-for-faceting)
 * in your Algolia settings.
 *
 * The values inside this attribute must be JavaScript numbers (not strings).
 */
var rangeSlider = function rangeSlider(widgetParams) {
  var _ref3 = widgetParams || {},
    container = _ref3.container,
    attribute = _ref3.attribute,
    min = _ref3.min,
    max = _ref3.max,
    _ref3$cssClasses = _ref3.cssClasses,
    userCssClasses = _ref3$cssClasses === void 0 ? {} : _ref3$cssClasses,
    step = _ref3.step,
    _ref3$pips = _ref3.pips,
    pips = _ref3$pips === void 0 ? true : _ref3$pips,
    _ref3$precision = _ref3.precision,
    precision = _ref3$precision === void 0 ? 0 : _ref3$precision,
    _ref3$tooltips = _ref3.tooltips,
    tooltips = _ref3$tooltips === void 0 ? true : _ref3$tooltips;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var containerNode = getContainerNode(container);
  var cssClasses = {
    root: cx(suit(), userCssClasses.root),
    disabledRoot: cx(suit({
      modifierName: 'disabled'
    }), userCssClasses.disabledRoot)
  };
  var specializedRenderer = renderer({
    containerNode: containerNode,
    step: step,
    pips: pips,
    tooltips: tooltips,
    cssClasses: cssClasses
  });
  var makeWidget = connectRange(specializedRenderer, function () {
    return render(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    attribute: attribute,
    min: min,
    max: max,
    precision: precision
  })), {}, {
    $$type: 'ais.rangeSlider',
    $$widgetType: 'ais.rangeSlider'
  });
};
export default rangeSlider;