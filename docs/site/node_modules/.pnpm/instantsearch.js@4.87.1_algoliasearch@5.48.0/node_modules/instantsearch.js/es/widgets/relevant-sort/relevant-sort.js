function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
import { cx } from 'instantsearch-ui-components';
import { h, render } from 'preact';
import RelevantSort from "../../components/RelevantSort/RelevantSort.js";
import connectRelevantSort from "../../connectors/relevant-sort/connectRelevantSort.js";
import { component } from "../../lib/suit.js";
import { getContainerNode, createDocumentationMessageGenerator } from "../../lib/utils/index.js";
import defaultTemplates from "./defaultTemplates.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'relevant-sort'
});
var suit = component('RelevantSort');
var renderer = function renderer(_ref) {
  var containerNode = _ref.containerNode,
    cssClasses = _ref.cssClasses,
    templates = _ref.templates;
  return function (_ref2) {
    var isRelevantSorted = _ref2.isRelevantSorted,
      isVirtualReplica = _ref2.isVirtualReplica,
      refine = _ref2.refine;
    render(h(RelevantSort, {
      cssClasses: cssClasses,
      templates: templates,
      isRelevantSorted: isRelevantSorted,
      isVirtualReplica: isVirtualReplica,
      refine: refine
    }), containerNode);
  };
};
var relevantSort = function relevantSort(widgetParams) {
  var container = widgetParams.container,
    _widgetParams$templat = widgetParams.templates,
    userTemplates = _widgetParams$templat === void 0 ? {} : _widgetParams$templat,
    _widgetParams$cssClas = widgetParams.cssClasses,
    userCssClasses = _widgetParams$cssClas === void 0 ? {} : _widgetParams$cssClas;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var containerNode = getContainerNode(container);
  var cssClasses = {
    root: cx(suit(), userCssClasses.root),
    text: cx(suit({
      descendantName: 'text'
    }), userCssClasses.text),
    button: cx(suit({
      descendantName: 'button'
    }), userCssClasses.button)
  };
  var templates = _objectSpread(_objectSpread({}, defaultTemplates), userTemplates);
  var specializedRenderer = renderer({
    containerNode: containerNode,
    cssClasses: cssClasses,
    renderState: {},
    templates: templates
  });
  var makeWidget = connectRelevantSort(specializedRenderer, function () {
    render(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({})), {}, {
    $$widgetType: 'ais.relevantSort'
  });
};
export default relevantSort;