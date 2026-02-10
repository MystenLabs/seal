"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _CurrentRefinements = _interopRequireDefault(require("../../components/CurrentRefinements/CurrentRefinements"));
var _connectCurrentRefinements = _interopRequireDefault(require("../../connectors/current-refinements/connectCurrentRefinements"));
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
  name: 'current-refinements'
});
var suit = (0, _suit.component)('CurrentRefinements');
var renderer = function renderer(_ref, isFirstRender) {
  var items = _ref.items,
    widgetParams = _ref.widgetParams,
    canRefine = _ref.canRefine;
  if (isFirstRender) {
    return;
  }
  var _ref2 = widgetParams,
    container = _ref2.container,
    cssClasses = _ref2.cssClasses;
  (0, _preact.render)((0, _preact.h)(_CurrentRefinements.default, {
    cssClasses: cssClasses,
    items: items,
    canRefine: canRefine
  }), container);
};
var currentRefinements = function currentRefinements(widgetParams) {
  var _ref3 = widgetParams || {},
    container = _ref3.container,
    includedAttributes = _ref3.includedAttributes,
    excludedAttributes = _ref3.excludedAttributes,
    _ref3$cssClasses = _ref3.cssClasses,
    userCssClasses = _ref3$cssClasses === void 0 ? {} : _ref3$cssClasses,
    transformItems = _ref3.transformItems;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var containerNode = (0, _utils.getContainerNode)(container);
  var cssClasses = {
    root: (0, _instantsearchUiComponents.cx)(suit(), userCssClasses.root),
    noRefinementRoot: (0, _instantsearchUiComponents.cx)(suit({
      modifierName: 'noRefinement'
    }), userCssClasses.noRefinementRoot),
    list: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'list'
    }), userCssClasses.list),
    item: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'item'
    }), userCssClasses.item),
    label: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'label'
    }), userCssClasses.label),
    category: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'category'
    }), userCssClasses.category),
    categoryLabel: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'categoryLabel'
    }), userCssClasses.categoryLabel),
    delete: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'delete'
    }), userCssClasses.delete)
  };
  var makeWidget = (0, _connectCurrentRefinements.default)(renderer, function () {
    return (0, _preact.render)(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    container: containerNode,
    cssClasses: cssClasses,
    includedAttributes: includedAttributes,
    excludedAttributes: excludedAttributes,
    transformItems: transformItems
  })), {}, {
    $$widgetType: 'ais.currentRefinements'
  });
};
var _default = exports.default = currentRefinements;