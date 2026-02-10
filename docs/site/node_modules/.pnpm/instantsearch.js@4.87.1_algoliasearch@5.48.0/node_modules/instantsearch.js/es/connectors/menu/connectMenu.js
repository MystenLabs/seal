var _excluded = ["name", "escapedValue", "path"];
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function _objectWithoutProperties(e, t) { if (null == e) return {}; var o, r, i = _objectWithoutPropertiesLoose(e, t); if (Object.getOwnPropertySymbols) { var n = Object.getOwnPropertySymbols(e); for (r = 0; r < n.length; r++) o = n[r], -1 === t.indexOf(o) && {}.propertyIsEnumerable.call(e, o) && (i[o] = e[o]); } return i; }
function _objectWithoutPropertiesLoose(r, e) { if (null == r) return {}; var t = {}; for (var n in r) if ({}.hasOwnProperty.call(r, n)) { if (-1 !== e.indexOf(n)) continue; t[n] = r[n]; } return t; }
function _slicedToArray(r, e) { return _arrayWithHoles(r) || _iterableToArrayLimit(r, e) || _unsupportedIterableToArray(r, e) || _nonIterableRest(); }
function _nonIterableRest() { throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
function _iterableToArrayLimit(r, l) { var t = null == r ? null : "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"]; if (null != t) { var e, n, i, u, a = [], f = !0, o = !1; try { if (i = (t = t.call(r)).next, 0 === l) { if (Object(t) !== t) return; f = !1; } else for (; !(f = (e = i.call(t)).done) && (a.push(e.value), a.length !== l); f = !0); } catch (r) { o = !0, n = r; } finally { try { if (!f && null != t.return && (u = t.return(), Object(u) !== u)) return; } finally { if (o) throw n; } } return a; } }
function _arrayWithHoles(r) { if (Array.isArray(r)) return r; }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
import { checkRendering, createDocumentationMessageGenerator, createSendEventForFacet, noop, warning } from "../../lib/utils/index.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'menu',
  connector: true
});
var DEFAULT_SORT = ['isRefined', 'name:asc'];
/**
 * **Menu** connector provides the logic to build a widget that will give the user the ability to choose a single value for a specific facet. The typical usage of menu is for navigation in categories.
 *
 * This connector provides a `toggleShowMore()` function to display more or less items and a `refine()`
 * function to select an item. While selecting a new element, the `refine` will also unselect the
 * one that is currently selected.
 *
 * **Requirement:** the attribute passed as `attribute` must be present in "attributes for faceting" on the Algolia dashboard or configured as attributesForFaceting via a set settings call to the Algolia API.
 */
var connectMenu = function connectMenu(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : noop;
  checkRendering(renderFn, withUsage());
  return function (widgetParams) {
    var _ref = widgetParams || {},
      attribute = _ref.attribute,
      _ref$limit = _ref.limit,
      limit = _ref$limit === void 0 ? 10 : _ref$limit,
      _ref$showMore = _ref.showMore,
      showMore = _ref$showMore === void 0 ? false : _ref$showMore,
      _ref$showMoreLimit = _ref.showMoreLimit,
      showMoreLimit = _ref$showMoreLimit === void 0 ? 20 : _ref$showMoreLimit,
      _ref$sortBy = _ref.sortBy,
      sortBy = _ref$sortBy === void 0 ? DEFAULT_SORT : _ref$sortBy,
      _ref$transformItems = _ref.transformItems,
      transformItems = _ref$transformItems === void 0 ? function (items) {
        return items;
      } : _ref$transformItems;
    if (!attribute) {
      throw new Error(withUsage('The `attribute` option is required.'));
    }
    if (showMore === true && showMoreLimit <= limit) {
      throw new Error(withUsage('The `showMoreLimit` option must be greater than `limit`.'));
    }
    var sendEvent;
    var _createURL;
    var _refine;

    // Provide the same function to the `renderFn` so that way the user
    // has to only bind it once when `isFirstRendering` for instance
    var isShowingMore = false;
    var toggleShowMore = function toggleShowMore() {};
    function createToggleShowMore(renderOptions, widget) {
      return function () {
        isShowingMore = !isShowingMore;
        widget.render(renderOptions);
      };
    }
    function cachedToggleShowMore() {
      toggleShowMore();
    }
    function getLimit() {
      return isShowingMore ? showMoreLimit : limit;
    }
    return {
      $$type: 'ais.menu',
      init: function init(initOptions) {
        var instantSearchInstance = initOptions.instantSearchInstance;
        renderFn(_objectSpread(_objectSpread({}, this.getWidgetRenderState(initOptions)), {}, {
          instantSearchInstance: instantSearchInstance
        }), true);
      },
      render: function render(renderOptions) {
        var instantSearchInstance = renderOptions.instantSearchInstance;
        renderFn(_objectSpread(_objectSpread({}, this.getWidgetRenderState(renderOptions)), {}, {
          instantSearchInstance: instantSearchInstance
        }), false);
      },
      dispose: function dispose(_ref2) {
        var state = _ref2.state;
        unmountFn();
        return state.removeHierarchicalFacet(attribute).setQueryParameter('maxValuesPerFacet', undefined);
      },
      getRenderState: function getRenderState(renderState, renderOptions) {
        return _objectSpread(_objectSpread({}, renderState), {}, {
          menu: _objectSpread(_objectSpread({}, renderState.menu), {}, _defineProperty({}, attribute, this.getWidgetRenderState(renderOptions)))
        });
      },
      getWidgetRenderState: function getWidgetRenderState(renderOptions) {
        var _this = this;
        var results = renderOptions.results,
          createURL = renderOptions.createURL,
          instantSearchInstance = renderOptions.instantSearchInstance,
          helper = renderOptions.helper;
        var items = [];
        var canToggleShowMore = false;
        if (!sendEvent) {
          sendEvent = createSendEventForFacet({
            instantSearchInstance: instantSearchInstance,
            helper: helper,
            attribute: attribute,
            widgetType: this.$$type
          });
        }
        if (!_createURL) {
          _createURL = function _createURL(facetValue) {
            return createURL(function (uiState) {
              return _this.getWidgetUiState(uiState, {
                searchParameters: helper.state.resetPage().toggleFacetRefinement(attribute, facetValue),
                helper: helper
              });
            });
          };
        }
        if (!_refine) {
          _refine = function _refine(facetValue) {
            var _helper$getHierarchic = helper.getHierarchicalFacetBreadcrumb(attribute),
              _helper$getHierarchic2 = _slicedToArray(_helper$getHierarchic, 1),
              refinedItem = _helper$getHierarchic2[0];
            sendEvent('click:internal', facetValue ? facetValue : refinedItem);
            helper.toggleFacetRefinement(attribute, facetValue ? facetValue : refinedItem).search();
          };
        }
        if (renderOptions.results) {
          toggleShowMore = createToggleShowMore(renderOptions, this);
        }
        if (results) {
          var facetValues = results.getFacetValues(attribute, {
            sortBy: sortBy,
            facetOrdering: sortBy === DEFAULT_SORT
          });
          var facetItems = facetValues && !Array.isArray(facetValues) && facetValues.data ? facetValues.data : [];
          canToggleShowMore = showMore && (isShowingMore || facetItems.length > getLimit());
          items = transformItems(facetItems.slice(0, getLimit()).map(function (_ref3) {
            var label = _ref3.name,
              value = _ref3.escapedValue,
              path = _ref3.path,
              item = _objectWithoutProperties(_ref3, _excluded);
            return _objectSpread(_objectSpread({}, item), {}, {
              label: label,
              value: value
            });
          }), {
            results: results
          });
        }
        return {
          items: items,
          createURL: _createURL,
          refine: _refine,
          sendEvent: sendEvent,
          canRefine: items.length > 0,
          widgetParams: widgetParams,
          isShowingMore: isShowingMore,
          toggleShowMore: cachedToggleShowMore,
          canToggleShowMore: canToggleShowMore
        };
      },
      getWidgetUiState: function getWidgetUiState(uiState, _ref4) {
        var searchParameters = _ref4.searchParameters;
        var _searchParameters$get = searchParameters.getHierarchicalFacetBreadcrumb(attribute),
          _searchParameters$get2 = _slicedToArray(_searchParameters$get, 1),
          value = _searchParameters$get2[0];
        return removeEmptyRefinementsFromUiState(_objectSpread(_objectSpread({}, uiState), {}, {
          menu: _objectSpread(_objectSpread({}, uiState.menu), {}, _defineProperty({}, attribute, value))
        }), attribute);
      },
      getWidgetSearchParameters: function getWidgetSearchParameters(searchParameters, _ref5) {
        var uiState = _ref5.uiState;
        var value = uiState.menu && uiState.menu[attribute];
        if (searchParameters.isConjunctiveFacet(attribute) || searchParameters.isDisjunctiveFacet(attribute)) {
          process.env.NODE_ENV === 'development' ? warning(false, "Menu: Attribute \"".concat(attribute, "\" is already used by another widget applying conjunctive or disjunctive faceting.\nAs this is not supported, please make sure to remove this other widget or this Menu widget will not work at all.")) : void 0;
          return searchParameters;
        }
        var withFacetConfiguration = searchParameters.removeHierarchicalFacet(attribute).addHierarchicalFacet({
          name: attribute,
          attributes: [attribute]
        });
        var currentMaxValuesPerFacet = withFacetConfiguration.maxValuesPerFacet || 0;
        var nextMaxValuesPerFacet = Math.max(currentMaxValuesPerFacet, showMore ? showMoreLimit : limit);
        var withMaxValuesPerFacet = withFacetConfiguration.setQueryParameter('maxValuesPerFacet', nextMaxValuesPerFacet);
        if (!value) {
          return withMaxValuesPerFacet.setQueryParameters({
            hierarchicalFacetsRefinements: _objectSpread(_objectSpread({}, withMaxValuesPerFacet.hierarchicalFacetsRefinements), {}, _defineProperty({}, attribute, []))
          });
        }
        return withMaxValuesPerFacet.addHierarchicalFacetRefinement(attribute, value);
      }
    };
  };
};
function removeEmptyRefinementsFromUiState(indexUiState, attribute) {
  if (!indexUiState.menu) {
    return indexUiState;
  }
  if (indexUiState.menu[attribute] === undefined) {
    delete indexUiState.menu[attribute];
  }
  if (Object.keys(indexUiState.menu).length === 0) {
    delete indexUiState.menu;
  }
  return indexUiState;
}
export default connectMenu;