function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
import { cx } from 'instantsearch-ui-components';
import { h, render } from 'preact';
import CustomData from "../../components/QueryRuleCustomData/QueryRuleCustomData.js";
import connectQueryRules from "../../connectors/query-rules/connectQueryRules.js";
import { component } from "../../lib/suit.js";
import { getContainerNode, createDocumentationMessageGenerator } from "../../lib/utils/index.js";
export var defaultTemplates = {
  default: function _default(_ref) {
    var items = _ref.items;
    return JSON.stringify(items, null, 2);
  }
};
var withUsage = createDocumentationMessageGenerator({
  name: 'query-rule-custom-data'
});
var suit = component('QueryRuleCustomData');
var renderer = function renderer(_ref2) {
  var containerNode = _ref2.containerNode,
    cssClasses = _ref2.cssClasses,
    templates = _ref2.templates;
  return function (_ref3) {
    var items = _ref3.items;
    render(h(CustomData, {
      cssClasses: cssClasses,
      templates: templates,
      items: items
    }), containerNode);
  };
};
var queryRuleCustomData = function queryRuleCustomData(widgetParams) {
  var _ref4 = widgetParams || {},
    container = _ref4.container,
    _ref4$cssClasses = _ref4.cssClasses,
    userCssClasses = _ref4$cssClasses === void 0 ? {} : _ref4$cssClasses,
    _ref4$templates = _ref4.templates,
    userTemplates = _ref4$templates === void 0 ? {} : _ref4$templates,
    _ref4$transformItems = _ref4.transformItems,
    transformItems = _ref4$transformItems === void 0 ? function (items) {
      return items;
    } : _ref4$transformItems;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var cssClasses = {
    root: cx(suit(), userCssClasses.root)
  };
  var containerNode = getContainerNode(container);
  var templates = _objectSpread(_objectSpread({}, defaultTemplates), userTemplates);
  var specializedRenderer = renderer({
    containerNode: containerNode,
    cssClasses: cssClasses,
    renderState: {},
    templates: templates
  });
  var makeWidget = connectQueryRules(specializedRenderer, function () {
    render(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    transformItems: transformItems
  })), {}, {
    $$widgetType: 'ais.queryRuleCustomData'
  });
};
export default queryRuleCustomData;