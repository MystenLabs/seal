function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
var _excluded = ["page"],
  _excluded2 = ["clickAnalytics", "userToken"];
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _toConsumableArray(r) { return _arrayWithoutHoles(r) || _iterableToArray(r) || _unsupportedIterableToArray(r) || _nonIterableSpread(); }
function _nonIterableSpread() { throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _iterableToArray(r) { if ("undefined" != typeof Symbol && null != r[Symbol.iterator] || null != r["@@iterator"]) return Array.from(r); }
function _arrayWithoutHoles(r) { if (Array.isArray(r)) return _arrayLikeToArray(r); }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
function _objectWithoutProperties(e, t) { if (null == e) return {}; var o, r, i = _objectWithoutPropertiesLoose(e, t); if (Object.getOwnPropertySymbols) { var n = Object.getOwnPropertySymbols(e); for (r = 0; r < n.length; r++) o = n[r], -1 === t.indexOf(o) && {}.propertyIsEnumerable.call(e, o) && (i[o] = e[o]); } return i; }
function _objectWithoutPropertiesLoose(r, e) { if (null == r) return {}; var t = {}; for (var n in r) if ({}.hasOwnProperty.call(r, n)) { if (-1 !== e.indexOf(n)) continue; t[n] = r[n]; } return t; }
import { escapeHits, TAG_PLACEHOLDER, checkRendering, createDocumentationMessageGenerator, isEqual, addAbsolutePosition, addQueryID, noop, createSendEventForHits, createBindEventForHits, walkIndex } from "../../lib/utils/index.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'infinite-hits',
  connector: true
});
function getStateWithoutPage(state) {
  var _ref = state || {},
    page = _ref.page,
    rest = _objectWithoutProperties(_ref, _excluded);
  return rest;
}
function normalizeState(state) {
  var _ref2 = state || {},
    clickAnalytics = _ref2.clickAnalytics,
    userToken = _ref2.userToken,
    rest = _objectWithoutProperties(_ref2, _excluded2);
  return rest;
}
function getInMemoryCache() {
  var cachedHits = null;
  var cachedState = null;
  return {
    read: function read(_ref3) {
      var state = _ref3.state;
      return isEqual(cachedState, getStateWithoutPage(state)) ? cachedHits : null;
    },
    write: function write(_ref4) {
      var state = _ref4.state,
        hits = _ref4.hits;
      cachedState = getStateWithoutPage(state);
      cachedHits = hits;
    }
  };
}
function extractHitsFromCachedHits(cachedHits) {
  return Object.keys(cachedHits).map(Number).sort(function (a, b) {
    return a - b;
  }).reduce(function (acc, page) {
    return acc.concat(cachedHits[page]);
  }, []);
}
export default (function connectInfiniteHits(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : noop;
  checkRendering(renderFn, withUsage());
  return function (widgetParams) {
    var _ref5 = widgetParams || {},
      _ref5$escapeHTML = _ref5.escapeHTML,
      escapeHTML = _ref5$escapeHTML === void 0 ? true : _ref5$escapeHTML,
      _ref5$transformItems = _ref5.transformItems,
      transformItems = _ref5$transformItems === void 0 ? function (items) {
        return items;
      } : _ref5$transformItems,
      _ref5$cache = _ref5.cache,
      cache = _ref5$cache === void 0 ? getInMemoryCache() : _ref5$cache;
    var showPrevious;
    var showMore;
    var sendEvent;
    var bindEvent;
    var getFirstReceivedPage = function getFirstReceivedPage(state, cachedHits) {
      var _state$page = state.page,
        page = _state$page === void 0 ? 0 : _state$page;
      var pages = Object.keys(cachedHits).map(Number);
      if (pages.length === 0) {
        return page;
      } else {
        return Math.min.apply(Math, [page].concat(_toConsumableArray(pages)));
      }
    };
    var getLastReceivedPage = function getLastReceivedPage(state, cachedHits) {
      var _state$page2 = state.page,
        page = _state$page2 === void 0 ? 0 : _state$page2;
      var pages = Object.keys(cachedHits).map(Number);
      if (pages.length === 0) {
        return page;
      } else {
        return Math.max.apply(Math, [page].concat(_toConsumableArray(pages)));
      }
    };
    var getShowPrevious = function getShowPrevious(helper, getCachedHits) {
      return function () {
        var cachedHits = getCachedHits();
        // Using the helper's `overrideStateWithoutTriggeringChangeEvent` method
        // avoid updating the browser URL when the user displays the previous page.
        helper.overrideStateWithoutTriggeringChangeEvent(_objectSpread(_objectSpread({}, helper.state), {}, {
          page: getFirstReceivedPage(helper.state, cachedHits) - 1
        })).searchWithoutTriggeringOnStateChange();
      };
    };
    var getShowMore = function getShowMore(helper, getCachedHits) {
      return function () {
        var cachedHits = getCachedHits();
        helper.setPage(getLastReceivedPage(helper.state, cachedHits) + 1).search();
      };
    };
    return {
      $$type: 'ais.infiniteHits',
      init: function init(initOptions) {
        renderFn(_objectSpread(_objectSpread({}, this.getWidgetRenderState(initOptions)), {}, {
          instantSearchInstance: initOptions.instantSearchInstance
        }), true);
      },
      render: function render(renderOptions) {
        var instantSearchInstance = renderOptions.instantSearchInstance;
        var widgetRenderState = this.getWidgetRenderState(renderOptions);
        renderFn(_objectSpread(_objectSpread({}, widgetRenderState), {}, {
          instantSearchInstance: instantSearchInstance
        }), false);
        sendEvent('view:internal', widgetRenderState.currentPageHits);
      },
      getRenderState: function getRenderState(renderState, renderOptions
      // Type is explicitly redefined, to avoid having the TWidgetParams type in the definition
      ) {
        return _objectSpread(_objectSpread({}, renderState), {}, {
          infiniteHits: this.getWidgetRenderState(renderOptions)
        });
      },
      getWidgetRenderState: function getWidgetRenderState(_ref6) {
        var _results$renderingCon, _results$renderingCon2, _results$renderingCon3;
        var results = _ref6.results,
          helper = _ref6.helper,
          parent = _ref6.parent,
          existingState = _ref6.state,
          instantSearchInstance = _ref6.instantSearchInstance;
        var getCacheHits = function getCacheHits() {
          var state = parent.getPreviousState() || existingState;
          return cache.read({
            state: normalizeState(state)
          }) || {};
        };
        var isFirstPage;
        var currentPageHits = [];
        /**
         * We bail out of optimistic UI here, as the cache is based on search
         * parameters, and we don't want to invalidate the cache when the search
         * is loading.
         */
        var state = parent.getPreviousState() || existingState;
        var cachedHits = getCacheHits();
        var banner = results === null || results === void 0 ? void 0 : (_results$renderingCon = results.renderingContent) === null || _results$renderingCon === void 0 ? void 0 : (_results$renderingCon2 = _results$renderingCon.widgets) === null || _results$renderingCon2 === void 0 ? void 0 : (_results$renderingCon3 = _results$renderingCon2.banners) === null || _results$renderingCon3 === void 0 ? void 0 : _results$renderingCon3[0];
        if (!showPrevious) {
          showPrevious = function showPrevious() {
            return getShowPrevious(helper, getCacheHits)();
          };
          showMore = function showMore() {
            return getShowMore(helper, getCacheHits)();
          };
        }
        if (!sendEvent) {
          sendEvent = createSendEventForHits({
            instantSearchInstance: instantSearchInstance,
            helper: helper,
            widgetType: this.$$type
          });
          bindEvent = createBindEventForHits({
            helper: helper,
            widgetType: this.$$type,
            instantSearchInstance: instantSearchInstance
          });
        }
        if (!results) {
          isFirstPage = state.page === undefined || getFirstReceivedPage(state, cachedHits) === 0;
        } else {
          var _state$disjunctiveFac, _state$hierarchicalFa;
          var _state$page3 = state.page,
            _page = _state$page3 === void 0 ? 0 : _state$page3;
          if (escapeHTML && results.hits.length > 0) {
            results.hits = escapeHits(results.hits);
          }
          var hitsWithAbsolutePosition = addAbsolutePosition(results.hits, results.page, results.hitsPerPage);
          var hitsWithAbsolutePositionAndQueryID = addQueryID(hitsWithAbsolutePosition, results.queryID);
          var transformedHits = transformItems(hitsWithAbsolutePositionAndQueryID, {
            results: results
          });

          /*
            With dynamic widgets, facets are not included in the state before their relevant widgets are mounted. Until then, we need to bail out of writing this incomplete state representation in cache.
          */
          var hasDynamicWidgets = false;
          walkIndex(instantSearchInstance.mainIndex, function (indexWidget) {
            if (!hasDynamicWidgets && indexWidget.getWidgets().some(function (_ref7) {
              var $$type = _ref7.$$type;
              return $$type === 'ais.dynamicWidgets';
            })) {
              hasDynamicWidgets = true;
            }
          });
          var hasNoFacets = !((_state$disjunctiveFac = state.disjunctiveFacets) !== null && _state$disjunctiveFac !== void 0 && _state$disjunctiveFac.length) && !(state.facets || []).filter(function (f) {
            return f !== '*';
          }).length && !((_state$hierarchicalFa = state.hierarchicalFacets) !== null && _state$hierarchicalFa !== void 0 && _state$hierarchicalFa.length);
          if (cachedHits[_page] === undefined && !results.__isArtificial && instantSearchInstance.status === 'idle' && !(hasDynamicWidgets && hasNoFacets)) {
            cachedHits[_page] = transformedHits;
            cache.write({
              state: normalizeState(state),
              hits: cachedHits
            });
          }
          currentPageHits = transformedHits;
          isFirstPage = getFirstReceivedPage(state, cachedHits) === 0;
        }
        var items = extractHitsFromCachedHits(cachedHits);
        var isLastPage = results ? results.nbPages <= getLastReceivedPage(state, cachedHits) + 1 : true;
        return {
          hits: items,
          items: items,
          currentPageHits: currentPageHits,
          sendEvent: sendEvent,
          bindEvent: bindEvent,
          banner: banner,
          results: results || undefined,
          showPrevious: showPrevious,
          showMore: showMore,
          isFirstPage: isFirstPage,
          isLastPage: isLastPage,
          widgetParams: widgetParams
        };
      },
      dispose: function dispose(_ref8) {
        var state = _ref8.state;
        unmountFn();
        var stateWithoutPage = state.setQueryParameter('page', undefined);
        if (!escapeHTML) {
          return stateWithoutPage;
        }
        return stateWithoutPage.setQueryParameters(Object.keys(TAG_PLACEHOLDER).reduce(function (acc, key) {
          return _objectSpread(_objectSpread({}, acc), {}, _defineProperty({}, key, undefined));
        }, {}));
      },
      getWidgetUiState: function getWidgetUiState(uiState, _ref9) {
        var searchParameters = _ref9.searchParameters;
        var page = searchParameters.page || 0;
        if (!page) {
          // return without adding `page` to uiState
          // because we don't want `page=1` in the URL
          return uiState;
        }
        return _objectSpread(_objectSpread({}, uiState), {}, {
          // The page in the UI state is incremented by one
          // to expose the user value (not `0`).
          page: page + 1
        });
      },
      getWidgetSearchParameters: function getWidgetSearchParameters(searchParameters, _ref0) {
        var uiState = _ref0.uiState;
        var widgetSearchParameters = searchParameters;
        if (escapeHTML) {
          // @MAJOR: set this globally, not in the InfiniteHits widget to allow InfiniteHits to be conditionally used
          widgetSearchParameters = searchParameters.setQueryParameters(TAG_PLACEHOLDER);
        }

        // The page in the search parameters is decremented by one
        // to get to the actual parameter value from the UI state.
        var page = uiState.page ? uiState.page - 1 : 0;
        return widgetSearchParameters.setQueryParameter('page', page);
      }
    };
  };
});