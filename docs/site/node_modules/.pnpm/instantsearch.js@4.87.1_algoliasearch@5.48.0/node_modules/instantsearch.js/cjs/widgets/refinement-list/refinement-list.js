"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _RefinementList = _interopRequireDefault(require("../../components/RefinementList/RefinementList"));
var _connectRefinementList = _interopRequireDefault(require("../../connectors/refinement-list/connectRefinementList"));
var _suit = require("../../lib/suit");
var _templating = require("../../lib/templating");
var _utils = require("../../lib/utils");
var _defaultTemplates = _interopRequireDefault(require("../search-box/defaultTemplates"));
var _defaultTemplates2 = _interopRequireDefault(require("./defaultTemplates"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'refinement-list'
});
var suit = (0, _suit.component)('RefinementList');
var searchBoxSuit = (0, _suit.component)('SearchBox');
var renderer = function renderer(_ref) {
  var containerNode = _ref.containerNode,
    cssClasses = _ref.cssClasses,
    templates = _ref.templates,
    searchBoxTemplates = _ref.searchBoxTemplates,
    renderState = _ref.renderState,
    showMore = _ref.showMore,
    searchable = _ref.searchable,
    searchablePlaceholder = _ref.searchablePlaceholder,
    searchableIsAlwaysActive = _ref.searchableIsAlwaysActive,
    searchableSelectOnSubmit = _ref.searchableSelectOnSubmit;
  return function (_ref2, isFirstRendering) {
    var refine = _ref2.refine,
      items = _ref2.items,
      createURL = _ref2.createURL,
      searchForItems = _ref2.searchForItems,
      isFromSearch = _ref2.isFromSearch,
      instantSearchInstance = _ref2.instantSearchInstance,
      toggleShowMore = _ref2.toggleShowMore,
      isShowingMore = _ref2.isShowingMore,
      hasExhaustiveItems = _ref2.hasExhaustiveItems,
      canToggleShowMore = _ref2.canToggleShowMore;
    if (isFirstRendering) {
      renderState.templateProps = (0, _templating.prepareTemplateProps)({
        defaultTemplates: _defaultTemplates2.default,
        templatesConfig: instantSearchInstance.templatesConfig,
        templates: templates
      });
      renderState.searchBoxTemplateProps = (0, _templating.prepareTemplateProps)({
        defaultTemplates: _defaultTemplates.default,
        templatesConfig: instantSearchInstance.templatesConfig,
        templates: searchBoxTemplates
      });
      return;
    }
    (0, _preact.render)((0, _preact.h)(_RefinementList.default, {
      createURL: createURL,
      cssClasses: cssClasses,
      facetValues: items,
      templateProps: renderState.templateProps,
      searchBoxTemplateProps: renderState.searchBoxTemplateProps,
      toggleRefinement: refine,
      searchFacetValues: searchable ? searchForItems : undefined,
      searchPlaceholder: searchablePlaceholder,
      searchIsAlwaysActive: searchableIsAlwaysActive,
      isFromSearch: isFromSearch,
      showMore: showMore && !isFromSearch && items.length > 0,
      toggleShowMore: toggleShowMore,
      isShowingMore: isShowingMore,
      hasExhaustiveItems: hasExhaustiveItems,
      canToggleShowMore: canToggleShowMore,
      searchableSelectOnSubmit: searchableSelectOnSubmit
    }), containerNode);
  };
};
/**
 * The refinement list widget is one of the most common widget that you can find
 * in a search UI. With this widget, the user can filter the dataset based on facets.
 *
 * The refinement list displays only the most relevant facets for the current search
 * context. The sort option only affects the facet that are returned by the engine,
 * not which facets are returned.
 *
 * This widget also implements search for facet values, which is a mini search inside the
 * values of the facets. This makes easy to deal with uncommon facet values.
 *
 * @requirements
 *
 * The attribute passed to `attribute` must be declared as an
 * [attribute for faceting](https://www.algolia.com/doc/guides/searching/faceting/#declaring-attributes-for-faceting)
 * in your Algolia settings.
 *
 * If you also want to use search for facet values on this attribute, you need to make it searchable using the [dashboard](https://www.algolia.com/explorer/display/) or using the [API](https://www.algolia.com/doc/guides/searching/faceting/#search-for-facet-values).
 */
var refinementList = function refinementList(widgetParams) {
  var _ref3 = widgetParams || {},
    container = _ref3.container,
    attribute = _ref3.attribute,
    operator = _ref3.operator,
    sortBy = _ref3.sortBy,
    limit = _ref3.limit,
    showMore = _ref3.showMore,
    showMoreLimit = _ref3.showMoreLimit,
    _ref3$searchable = _ref3.searchable,
    searchable = _ref3$searchable === void 0 ? false : _ref3$searchable,
    _ref3$searchablePlace = _ref3.searchablePlaceholder,
    searchablePlaceholder = _ref3$searchablePlace === void 0 ? 'Search...' : _ref3$searchablePlace,
    _ref3$searchableEscap = _ref3.searchableEscapeFacetValues,
    searchableEscapeFacetValues = _ref3$searchableEscap === void 0 ? true : _ref3$searchableEscap,
    _ref3$searchableIsAlw = _ref3.searchableIsAlwaysActive,
    searchableIsAlwaysActive = _ref3$searchableIsAlw === void 0 ? true : _ref3$searchableIsAlw,
    _ref3$searchableSelec = _ref3.searchableSelectOnSubmit,
    searchableSelectOnSubmit = _ref3$searchableSelec === void 0 ? true : _ref3$searchableSelec,
    _ref3$cssClasses = _ref3.cssClasses,
    userCssClasses = _ref3$cssClasses === void 0 ? {} : _ref3$cssClasses,
    _ref3$templates = _ref3.templates,
    templates = _ref3$templates === void 0 ? {} : _ref3$templates,
    transformItems = _ref3.transformItems;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var escapeFacetValues = searchable ? Boolean(searchableEscapeFacetValues) : false;
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
    searchBox: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'searchBox'
    }), userCssClasses.searchBox),
    label: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'label'
    }), userCssClasses.label),
    checkbox: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'checkbox'
    }), userCssClasses.checkbox),
    labelText: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'labelText'
    }), userCssClasses.labelText),
    count: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'count'
    }), userCssClasses.count),
    noResults: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'noResults'
    }), userCssClasses.noResults),
    showMore: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'showMore'
    }), userCssClasses.showMore),
    disabledShowMore: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'showMore',
      modifierName: 'disabled'
    }), userCssClasses.disabledShowMore),
    searchable: {
      root: (0, _instantsearchUiComponents.cx)(searchBoxSuit(), userCssClasses.searchableRoot),
      form: (0, _instantsearchUiComponents.cx)(searchBoxSuit({
        descendantName: 'form'
      }), userCssClasses.searchableForm),
      input: (0, _instantsearchUiComponents.cx)(searchBoxSuit({
        descendantName: 'input'
      }), userCssClasses.searchableInput),
      submit: (0, _instantsearchUiComponents.cx)(searchBoxSuit({
        descendantName: 'submit'
      }), userCssClasses.searchableSubmit),
      submitIcon: (0, _instantsearchUiComponents.cx)(searchBoxSuit({
        descendantName: 'submitIcon'
      }), userCssClasses.searchableSubmitIcon),
      reset: (0, _instantsearchUiComponents.cx)(searchBoxSuit({
        descendantName: 'reset'
      }), userCssClasses.searchableReset),
      resetIcon: (0, _instantsearchUiComponents.cx)(searchBoxSuit({
        descendantName: 'resetIcon'
      }), userCssClasses.searchableResetIcon),
      loadingIndicator: (0, _instantsearchUiComponents.cx)(searchBoxSuit({
        descendantName: 'loadingIndicator'
      }), userCssClasses.searchableLoadingIndicator),
      loadingIcon: (0, _instantsearchUiComponents.cx)(searchBoxSuit({
        descendantName: 'loadingIcon'
      }), userCssClasses.searchableLoadingIcon)
    }
  };
  var specializedRenderer = renderer({
    containerNode: containerNode,
    cssClasses: cssClasses,
    templates: templates,
    searchBoxTemplates: {
      submit: templates.searchableSubmit,
      reset: templates.searchableReset,
      loadingIndicator: templates.searchableLoadingIndicator
    },
    renderState: {},
    searchable: searchable,
    searchablePlaceholder: searchablePlaceholder,
    searchableIsAlwaysActive: searchableIsAlwaysActive,
    searchableSelectOnSubmit: searchableSelectOnSubmit,
    showMore: showMore
  });
  var makeWidget = (0, _connectRefinementList.default)(specializedRenderer, function () {
    return (0, _preact.render)(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    attribute: attribute,
    operator: operator,
    limit: limit,
    showMore: showMore,
    showMoreLimit: showMoreLimit,
    sortBy: sortBy,
    escapeFacetValues: escapeFacetValues,
    transformItems: transformItems
  })), {}, {
    $$widgetType: 'ais.refinementList'
  });
};
var _default = exports.default = refinementList;