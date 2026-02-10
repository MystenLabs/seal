"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _RefinementList = _interopRequireDefault(require("../../components/RefinementList/RefinementList"));
var _connectHierarchicalMenu = _interopRequireDefault(require("../../connectors/hierarchical-menu/connectHierarchicalMenu"));
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
  name: 'hierarchical-menu'
});
var suit = (0, _suit.component)('HierarchicalMenu');
var renderer = function renderer(_ref) {
  var cssClasses = _ref.cssClasses,
    containerNode = _ref.containerNode,
    showMore = _ref.showMore,
    templates = _ref.templates,
    renderState = _ref.renderState;
  return function (_ref2, isFirstRendering) {
    var createURL = _ref2.createURL,
      items = _ref2.items,
      refine = _ref2.refine,
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
    (0, _preact.render)((0, _preact.h)(_RefinementList.default, {
      createURL: createURL,
      cssClasses: cssClasses,
      facetValues: items,
      templateProps: renderState.templateProps,
      toggleRefinement: refine,
      showMore: showMore,
      toggleShowMore: toggleShowMore,
      isShowingMore: isShowingMore,
      canToggleShowMore: canToggleShowMore
    }), containerNode);
  };
};

/**
 * The hierarchical menu widget is used to create a navigation based on a hierarchy of facet attributes.
 *
 * It is commonly used for categories with subcategories.
 *
 * All attributes (lvl0, lvl1 here) must be declared as [attributes for faceting](https://www.algolia.com/doc/guides/searching/faceting/#declaring-attributes-for-faceting) in your
 * Algolia settings.
 *
 * By default, the separator we expect is ` > ` (with spaces) but you can use
 * a different one by using the `separator` option.
 * @requirements
 * Your objects must be formatted in a specific way to be
 * able to display hierarchical menus. Here's an example:
 *
 * ```javascript
 * {
 *   "objectID": "123",
 *   "name": "orange",
 *   "categories": {
 *     "lvl0": "fruits",
 *     "lvl1": "fruits > citrus"
 *   }
 * }
 * ```
 *
 * Every level must be specified entirely.
 * It's also possible to have multiple values per level, for example:
 *
 * ```javascript
 * {
 *   "objectID": "123",
 *   "name": "orange",
 *   "categories": {
 *     "lvl0": ["fruits", "vitamins"],
 *     "lvl1": ["fruits > citrus", "vitamins > C"]
 *   }
 * }
 * ```
 * @type {WidgetFactory}
 * @devNovel HierarchicalMenu
 * @category filter
 * @param {HierarchicalMenuWidgetParams} widgetParams The HierarchicalMenu widget options.
 * @return {Widget} A new HierarchicalMenu widget instance.
 * @example
 * search.addWidgets([
 *   instantsearch.widgets.hierarchicalMenu({
 *     container: '#hierarchical-categories',
 *     attributes: ['hierarchicalCategories.lvl0', 'hierarchicalCategories.lvl1', 'hierarchicalCategories.lvl2'],
 *   })
 * ]);
 */

var hierarchicalMenu = function hierarchicalMenu(widgetParams) {
  var _ref3 = widgetParams || {},
    container = _ref3.container,
    attributes = _ref3.attributes,
    separator = _ref3.separator,
    rootPath = _ref3.rootPath,
    showParentLevel = _ref3.showParentLevel,
    limit = _ref3.limit,
    _ref3$showMore = _ref3.showMore,
    showMore = _ref3$showMore === void 0 ? false : _ref3$showMore,
    showMoreLimit = _ref3.showMoreLimit,
    sortBy = _ref3.sortBy,
    transformItems = _ref3.transformItems,
    _ref3$templates = _ref3.templates,
    templates = _ref3$templates === void 0 ? {} : _ref3$templates,
    _ref3$cssClasses = _ref3.cssClasses,
    userCssClasses = _ref3$cssClasses === void 0 ? {} : _ref3$cssClasses;
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
    childList: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'list',
      modifierName: 'child'
    }), userCssClasses.childList),
    item: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'item'
    }), userCssClasses.item),
    selectedItem: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'item',
      modifierName: 'selected'
    }), userCssClasses.selectedItem),
    parentItem: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'item',
      modifierName: 'parent'
    }), userCssClasses.parentItem),
    link: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'link'
    }), userCssClasses.link),
    selectedItemLink: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'link',
      modifierName: 'selected'
    }), userCssClasses.selectedItemLink),
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
    cssClasses: cssClasses,
    containerNode: containerNode,
    templates: templates,
    showMore: showMore,
    renderState: {}
  });
  var makeWidget = (0, _connectHierarchicalMenu.default)(specializedRenderer, function () {
    return (0, _preact.render)(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    attributes: attributes,
    separator: separator,
    rootPath: rootPath,
    showParentLevel: showParentLevel,
    limit: limit,
    showMore: showMore,
    showMoreLimit: showMoreLimit,
    sortBy: sortBy,
    transformItems: transformItems
  })), {}, {
    $$widgetType: 'ais.hierarchicalMenu'
  });
};
var _default = exports.default = hierarchicalMenu;