"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _Selector = _interopRequireDefault(require("../../components/Selector/Selector"));
var _connectSortBy = _interopRequireDefault(require("../../connectors/sort-by/connectSortBy"));
var _suit = require("../../lib/suit");
var _utils = require("../../lib/utils");
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'sort-by'
});
var suit = (0, _suit.component)('SortBy');
var renderer = function renderer(_ref) {
  var containerNode = _ref.containerNode,
    cssClasses = _ref.cssClasses;
  return function (_ref2, isFirstRendering) {
    var currentRefinement = _ref2.currentRefinement,
      options = _ref2.options,
      refine = _ref2.refine;
    if (isFirstRendering) {
      return;
    }
    (0, _preact.render)((0, _preact.h)("div", {
      className: cssClasses.root
    }, (0, _preact.h)(_Selector.default, {
      cssClasses: cssClasses,
      currentValue: currentRefinement,
      options: options,
      setValue: refine,
      ariaLabel: "Sort results by"
    })), containerNode);
  };
};

/**
 * Sort by selector is a widget used for letting the user choose between different
 * indices that contains the same data with a different order / ranking formula.
 */
var sortBy = function sortBy(widgetParams) {
  var _ref3 = widgetParams || {},
    container = _ref3.container,
    items = _ref3.items,
    _ref3$cssClasses = _ref3.cssClasses,
    userCssClasses = _ref3$cssClasses === void 0 ? {} : _ref3$cssClasses,
    transformItems = _ref3.transformItems;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var containerNode = (0, _utils.getContainerNode)(container);
  var cssClasses = {
    root: (0, _instantsearchUiComponents.cx)(suit(), userCssClasses.root),
    select: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'select'
    }), userCssClasses.select),
    option: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'option'
    }), userCssClasses.option)
  };
  var specializedRenderer = renderer({
    containerNode: containerNode,
    cssClasses: cssClasses
  });
  var makeWidget = (0, _connectSortBy.default)(specializedRenderer, function () {
    return (0, _preact.render)(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    container: containerNode,
    items: items,
    transformItems: transformItems
  })), {}, {
    $$widgetType: 'ais.sortBy'
  });
};
var _default = exports.default = sortBy;