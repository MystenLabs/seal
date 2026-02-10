"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _RefinementList = _interopRequireDefault(require("../../components/RefinementList/RefinementList"));
var _connectMenu = _interopRequireDefault(require("../../connectors/menu/connectMenu"));
var _suit = require("../../lib/suit");
var _templating = require("../../lib/templating");
var _utils = require("../../lib/utils");
var _defaultTemplates = _interopRequireDefault(require("./defaultTemplates"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'menu'
});
var suit = (0, _suit.component)('Menu');
var renderer = function renderer(_ref) {
  var containerNode = _ref.containerNode,
    cssClasses = _ref.cssClasses,
    renderState = _ref.renderState,
    templates = _ref.templates,
    showMore = _ref.showMore;
  return function (_ref2, isFirstRendering) {
    var refine = _ref2.refine,
      items = _ref2.items,
      createURL = _ref2.createURL,
      instantSearchInstance = _ref2.instantSearchInstance,
      isShowingMore = _ref2.isShowingMore,
      toggleShowMore = _ref2.toggleShowMore,
      canToggleShowMore = _ref2.canToggleShowMore;
    if (isFirstRendering) {
      renderState.templateProps = (0, _templating.prepareTemplateProps)({
        defaultTemplates: _defaultTemplates.default,
        templatesConfig: instantSearchInstance.templatesConfig,
        templates: templates
      });
      return;
    }
    var facetValues = items.map(function (facetValue) {
      return _objectSpread(_objectSpread({}, facetValue), {}, {
        url: createURL(facetValue.value)
      });
    });
    (0, _preact.render)((0, _preact.h)(_RefinementList.default, {
      createURL: createURL,
      cssClasses: cssClasses,
      facetValues: facetValues,
      showMore: showMore,
      templateProps: renderState.templateProps,
      toggleRefinement: refine,
      toggleShowMore: toggleShowMore,
      isShowingMore: isShowingMore,
      canToggleShowMore: canToggleShowMore
    }), containerNode);
  };
};
var menu = function menu(widgetParams) {
  var _ref3 = widgetParams || {},
    container = _ref3.container,
    attribute = _ref3.attribute,
    sortBy = _ref3.sortBy,
    limit = _ref3.limit,
    showMore = _ref3.showMore,
    showMoreLimit = _ref3.showMoreLimit,
    _ref3$cssClasses = _ref3.cssClasses,
    userCssClasses = _ref3$cssClasses === void 0 ? {} : _ref3$cssClasses,
    _ref3$templates = _ref3.templates,
    templates = _ref3$templates === void 0 ? {} : _ref3$templates,
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
    selectedItem: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'item',
      modifierName: 'selected'
    }), userCssClasses.selectedItem),
    link: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'link'
    }), userCssClasses.link),
    label: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'label'
    }), userCssClasses.label),
    count: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'count'
    }), userCssClasses.count),
    showMore: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'showMore'
    }), userCssClasses.showMore),
    disabledShowMore: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'showMore',
      modifierName: 'disabled'
    }), userCssClasses.disabledShowMore)
  };
  var specializedRenderer = renderer({
    containerNode: containerNode,
    cssClasses: cssClasses,
    renderState: {},
    templates: templates,
    showMore: showMore
  });
  var makeWidget = (0, _connectMenu.default)(specializedRenderer, function () {
    return (0, _preact.render)(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    attribute: attribute,
    limit: limit,
    showMore: showMore,
    showMoreLimit: showMoreLimit,
    sortBy: sortBy,
    transformItems: transformItems
  })), {}, {
    $$widgetType: 'ais.menu'
  });
};
var _default = exports.default = menu;