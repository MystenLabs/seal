function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
var _excluded = ["name", "escapedValue"],
  _excluded2 = ["escapedValue", "value"];
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _objectWithoutProperties(e, t) { if (null == e) return {}; var o, r, i = _objectWithoutPropertiesLoose(e, t); if (Object.getOwnPropertySymbols) { var n = Object.getOwnPropertySymbols(e); for (r = 0; r < n.length; r++) o = n[r], -1 === t.indexOf(o) && {}.propertyIsEnumerable.call(e, o) && (i[o] = e[o]); } return i; }
function _objectWithoutPropertiesLoose(r, e) { if (null == r) return {}; var t = {}; for (var n in r) if ({}.hasOwnProperty.call(r, n)) { if (-1 !== e.indexOf(n)) continue; t[n] = r[n]; } return t; }
import { escapeFacets, TAG_PLACEHOLDER, TAG_REPLACEMENT, checkRendering, createDocumentationMessageGenerator, createSendEventForFacet, noop, warning } from "../../lib/utils/index.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'refinement-list',
  connector: true
});
var DEFAULT_SORT = ['isRefined', 'count:desc', 'name:asc'];
/**
 * **RefinementList** connector provides the logic to build a custom widget that
 * will let the user filter the results based on the values of a specific facet.
 *
 * **Requirement:** the attribute passed as `attribute` must be present in
 * attributesForFaceting of the searched index.
 *
 * This connector provides:
 * - a `refine()` function to select an item.
 * - a `toggleShowMore()` function to display more or less items
 * - a `searchForItems()` function to search within the items.
 */
var connectRefinementList = function connectRefinementList(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : noop;
  checkRendering(renderFn, withUsage());
  return function (widgetParams) {
    var _ref = widgetParams || {},
      attribute = _ref.attribute,
      _ref$operator = _ref.operator,
      operator = _ref$operator === void 0 ? 'or' : _ref$operator,
      _ref$limit = _ref.limit,
      limit = _ref$limit === void 0 ? 10 : _ref$limit,
      _ref$showMore = _ref.showMore,
      showMore = _ref$showMore === void 0 ? false : _ref$showMore,
      _ref$showMoreLimit = _ref.showMoreLimit,
      showMoreLimit = _ref$showMoreLimit === void 0 ? 20 : _ref$showMoreLimit,
      _ref$sortBy = _ref.sortBy,
      sortBy = _ref$sortBy === void 0 ? DEFAULT_SORT : _ref$sortBy,
      _ref$escapeFacetValue = _ref.escapeFacetValues,
      escapeFacetValues = _ref$escapeFacetValue === void 0 ? true : _ref$escapeFacetValue,
      _ref$transformItems = _ref.transformItems,
      transformItems = _ref$transformItems === void 0 ? function (items) {
        return items;
      } : _ref$transformItems;
    if (!attribute) {
      throw new Error(withUsage('The `attribute` option is required.'));
    }
    if (!/^(and|or)$/.test(operator)) {
      throw new Error(withUsage("The `operator` must one of: `\"and\"`, `\"or\"` (got \"".concat(operator, "\").")));
    }
    if (showMore === true && showMoreLimit <= limit) {
      throw new Error(withUsage('`showMoreLimit` should be greater than `limit`.'));
    }
    var formatItems = function formatItems(_ref2) {
      var label = _ref2.name,
        value = _ref2.escapedValue,
        item = _objectWithoutProperties(_ref2, _excluded);
      return _objectSpread(_objectSpread({}, item), {}, {
        value: value,
        label: label,
        highlighted: label
      });
    };
    var lastResultsFromMainSearch;
    var lastItemsFromMainSearch = [];
    var hasExhaustiveItems = true;
    var triggerRefine;
    var sendEvent;
    var isShowingMore = false;
    // Provide the same function to the `renderFn` so that way the user
    // has to only bind it once when `isFirstRendering` for instance
    var toggleShowMore = function toggleShowMore() {};
    function cachedToggleShowMore() {
      toggleShowMore();
    }
    function createToggleShowMore(renderOptions, widget) {
      return function () {
        isShowingMore = !isShowingMore;
        widget.render(renderOptions);
      };
    }
    function getLimit() {
      return isShowingMore ? showMoreLimit : limit;
    }
    var searchForFacetValues = function searchForFacetValues() {
      return function () {};
    };
    var createSearchForFacetValues = function createSearchForFacetValues(helper, widget) {
      return function (renderOptions) {
        return function (query) {
          var instantSearchInstance = renderOptions.instantSearchInstance,
            searchResults = renderOptions.results;
          if (query === '' && lastItemsFromMainSearch) {
            // render with previous data from the helper.
            renderFn(_objectSpread(_objectSpread({}, widget.getWidgetRenderState(_objectSpread(_objectSpread({}, renderOptions), {}, {
              results: lastResultsFromMainSearch
            }))), {}, {
              instantSearchInstance: instantSearchInstance
            }), false);
          } else {
            var tags = {
              highlightPreTag: escapeFacetValues ? TAG_PLACEHOLDER.highlightPreTag : TAG_REPLACEMENT.highlightPreTag,
              highlightPostTag: escapeFacetValues ? TAG_PLACEHOLDER.highlightPostTag : TAG_REPLACEMENT.highlightPostTag
            };
            helper.searchForFacetValues(attribute, query,
            // We cap the `maxFacetHits` value to 100 because the Algolia API
            // doesn't support a greater number.
            // See https://www.algolia.com/doc/api-reference/api-parameters/maxFacetHits/
            Math.min(getLimit(), 100), tags).then(function (results) {
              var facetValues = escapeFacetValues ? escapeFacets(results.facetHits) : results.facetHits;
              var normalizedFacetValues = transformItems(facetValues.map(function (_ref3) {
                var escapedValue = _ref3.escapedValue,
                  value = _ref3.value,
                  item = _objectWithoutProperties(_ref3, _excluded2);
                return _objectSpread(_objectSpread({}, item), {}, {
                  value: escapedValue,
                  label: value
                });
              }), {
                results: searchResults
              });
              renderFn(_objectSpread(_objectSpread({}, widget.getWidgetRenderState(_objectSpread(_objectSpread({}, renderOptions), {}, {
                results: lastResultsFromMainSearch
              }))), {}, {
                items: normalizedFacetValues,
                canToggleShowMore: false,
                canRefine: true,
                isFromSearch: true,
                instantSearchInstance: instantSearchInstance
              }), false);
            });
          }
        };
      };
    };
    return {
      $$type: 'ais.refinementList',
      init: function init(initOptions) {
        renderFn(_objectSpread(_objectSpread({}, this.getWidgetRenderState(initOptions)), {}, {
          instantSearchInstance: initOptions.instantSearchInstance
        }), true);
      },
      render: function render(renderOptions) {
        renderFn(_objectSpread(_objectSpread({}, this.getWidgetRenderState(renderOptions)), {}, {
          instantSearchInstance: renderOptions.instantSearchInstance
        }), false);
      },
      getRenderState: function getRenderState(renderState, renderOptions) {
        return _objectSpread(_objectSpread({}, renderState), {}, {
          refinementList: _objectSpread(_objectSpread({}, renderState.refinementList), {}, _defineProperty({}, attribute, this.getWidgetRenderState(renderOptions)))
        });
      },
      getWidgetRenderState: function getWidgetRenderState(renderOptions) {
        var _this = this;
        var results = renderOptions.results,
          state = renderOptions.state,
          _createURL = renderOptions.createURL,
          instantSearchInstance = renderOptions.instantSearchInstance,
          helper = renderOptions.helper;
        var items = [];
        var facetValues = [];
        if (!sendEvent || !triggerRefine || !searchForFacetValues) {
          sendEvent = createSendEventForFacet({
            instantSearchInstance: instantSearchInstance,
            helper: helper,
            attribute: attribute,
            widgetType: this.$$type
          });
          triggerRefine = function triggerRefine(facetValue) {
            sendEvent('click:internal', facetValue);
            helper.toggleFacetRefinement(attribute, facetValue).search();
          };
          searchForFacetValues = createSearchForFacetValues(helper, this);
        }
        if (results) {
          var values = results.getFacetValues(attribute, {
            sortBy: sortBy,
            facetOrdering: sortBy === DEFAULT_SORT
          });
          facetValues = values && Array.isArray(values) ? values : [];
          items = transformItems(facetValues.slice(0, getLimit()).map(formatItems), {
            results: results
          });
          var maxValuesPerFacetConfig = state.maxValuesPerFacet;
          var currentLimit = getLimit();
          // If the limit is the max number of facet retrieved it is impossible to know
          // if the facets are exhaustive. The only moment we are sure it is exhaustive
          // is when it is strictly under the number requested unless we know that another
          // widget has requested more values (maxValuesPerFacet > getLimit()).
          // Because this is used for making the search of facets unable or not, it is important
          // to be conservative here.
          hasExhaustiveItems = maxValuesPerFacetConfig > currentLimit ? facetValues.length <= currentLimit : facetValues.length < currentLimit;
          lastResultsFromMainSearch = results;
          lastItemsFromMainSearch = items;
          if (renderOptions.results) {
            toggleShowMore = createToggleShowMore(renderOptions, this);
          }
        }

        // Do not mistake searchForFacetValues and searchFacetValues which is the actual search
        // function
        var searchFacetValues = searchForFacetValues && searchForFacetValues(renderOptions);
        var canShowLess = isShowingMore && lastItemsFromMainSearch.length > limit;
        var canShowMore = showMore && !hasExhaustiveItems;
        var canToggleShowMore = canShowLess || canShowMore;
        return {
          createURL: function createURL(facetValue) {
            return _createURL(function (uiState) {
              return _this.getWidgetUiState(uiState, {
                searchParameters: state.resetPage().toggleFacetRefinement(attribute, facetValue),
                helper: helper
              });
            });
          },
          items: items,
          refine: triggerRefine,
          searchForItems: searchFacetValues,
          isFromSearch: false,
          canRefine: items.length > 0,
          widgetParams: widgetParams,
          isShowingMore: isShowingMore,
          canToggleShowMore: canToggleShowMore,
          toggleShowMore: cachedToggleShowMore,
          sendEvent: sendEvent,
          hasExhaustiveItems: hasExhaustiveItems
        };
      },
      dispose: function dispose(_ref4) {
        var state = _ref4.state;
        unmountFn();
        var withoutMaxValuesPerFacet = state.setQueryParameter('maxValuesPerFacet', undefined);
        if (operator === 'and') {
          return withoutMaxValuesPerFacet.removeFacet(attribute);
        }
        return withoutMaxValuesPerFacet.removeDisjunctiveFacet(attribute);
      },
      getWidgetUiState: function getWidgetUiState(uiState, _ref5) {
        var searchParameters = _ref5.searchParameters;
        var values = operator === 'or' ? searchParameters.getDisjunctiveRefinements(attribute) : searchParameters.getConjunctiveRefinements(attribute);
        return removeEmptyRefinementsFromUiState(_objectSpread(_objectSpread({}, uiState), {}, {
          refinementList: _objectSpread(_objectSpread({}, uiState.refinementList), {}, _defineProperty({}, attribute, values))
        }), attribute);
      },
      getWidgetSearchParameters: function getWidgetSearchParameters(searchParameters, _ref6) {
        var uiState = _ref6.uiState;
        var isDisjunctive = operator === 'or';
        if (searchParameters.isHierarchicalFacet(attribute)) {
          process.env.NODE_ENV === 'development' ? warning(false, "RefinementList: Attribute \"".concat(attribute, "\" is already used by another widget applying hierarchical faceting.\nAs this is not supported, please make sure to remove this other widget or this RefinementList widget will not work at all.")) : void 0;
          return searchParameters;
        }
        if (isDisjunctive && searchParameters.isConjunctiveFacet(attribute) || !isDisjunctive && searchParameters.isDisjunctiveFacet(attribute)) {
          process.env.NODE_ENV === 'development' ? warning(false, "RefinementList: Attribute \"".concat(attribute, "\" is used by another refinement list with a different operator.\nAs this is not supported, please make sure to only use this attribute with one of the two operators.")) : void 0;
          return searchParameters;
        }
        var values = uiState.refinementList && uiState.refinementList[attribute];
        var withFacetConfiguration = isDisjunctive ? searchParameters.addDisjunctiveFacet(attribute).removeDisjunctiveFacetRefinement(attribute) : searchParameters.addFacet(attribute).removeFacetRefinement(attribute);
        var currentMaxValuesPerFacet = withFacetConfiguration.maxValuesPerFacet || 0;
        var nextMaxValuesPerFacet = Math.max(currentMaxValuesPerFacet, showMore ? showMoreLimit : limit);
        var withMaxValuesPerFacet = withFacetConfiguration.setQueryParameter('maxValuesPerFacet', nextMaxValuesPerFacet);
        if (!values) {
          var key = isDisjunctive ? 'disjunctiveFacetsRefinements' : 'facetsRefinements';
          return withMaxValuesPerFacet.setQueryParameters(_defineProperty({}, key, _objectSpread(_objectSpread({}, withMaxValuesPerFacet[key]), {}, _defineProperty({}, attribute, []))));
        }
        return values.reduce(function (parameters, value) {
          return isDisjunctive ? parameters.addDisjunctiveFacetRefinement(attribute, value) : parameters.addFacetRefinement(attribute, value);
        }, withMaxValuesPerFacet);
      }
    };
  };
};
function removeEmptyRefinementsFromUiState(indexUiState, attribute) {
  if (!indexUiState.refinementList) {
    return indexUiState;
  }
  if (!indexUiState.refinementList[attribute] || indexUiState.refinementList[attribute].length === 0) {
    delete indexUiState.refinementList[attribute];
  }
  if (Object.keys(indexUiState.refinementList).length === 0) {
    delete indexUiState.refinementList;
  }
  return indexUiState;
}
export default connectRefinementList;