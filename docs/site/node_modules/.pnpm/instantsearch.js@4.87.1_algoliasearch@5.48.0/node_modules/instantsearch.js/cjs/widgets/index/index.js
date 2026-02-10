"use strict";

function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _algoliasearchHelper = _interopRequireDefault(require("algoliasearch-helper"));
var _utils = require("../../lib/utils");
var _addWidgetId = require("../../lib/utils/addWidgetId");
var _excluded = ["initialSearchParameters"],
  _excluded2 = ["initialRecommendParameters"];
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
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
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'index-widget'
});
/**
 * This is the same content as helper._change / setState, but allowing for extra
 * UiState to be synchronized.
 * see: https://github.com/algolia/algoliasearch-helper-js/blob/6b835ffd07742f2d6b314022cce6848f5cfecd4a/src/algoliasearch.helper.js#L1311-L1324
 */
function privateHelperSetState(helper, _ref) {
  var state = _ref.state,
    recommendState = _ref.recommendState,
    isPageReset = _ref.isPageReset,
    _uiState = _ref._uiState;
  if (state !== helper.state) {
    helper.state = state;
    helper.emit('change', {
      state: helper.state,
      results: helper.lastResults,
      isPageReset: isPageReset,
      _uiState: _uiState
    });
  }
  if (recommendState !== helper.recommendState) {
    helper.recommendState = recommendState;

    // eslint-disable-next-line no-warning-comments
    // TODO: emit "change" event when events for Recommend are implemented
  }
}
function getLocalWidgetsUiState(widgets, widgetStateOptions) {
  var initialUiState = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};
  return widgets.reduce(function (uiState, widget) {
    if ((0, _utils.isIndexWidget)(widget)) {
      return uiState;
    }
    if (!widget.getWidgetUiState && !widget.getWidgetState) {
      return uiState;
    }
    if (widget.getWidgetUiState) {
      return widget.getWidgetUiState(uiState, widgetStateOptions);
    }
    return widget.getWidgetState(uiState, widgetStateOptions);
  }, initialUiState);
}
function getLocalWidgetsSearchParameters(widgets, widgetSearchParametersOptions) {
  var initialSearchParameters = widgetSearchParametersOptions.initialSearchParameters,
    rest = _objectWithoutProperties(widgetSearchParametersOptions, _excluded);
  return widgets.reduce(function (state, widget) {
    if (!widget.getWidgetSearchParameters || (0, _utils.isIndexWidget)(widget)) {
      return state;
    }
    if (widget.dependsOn === 'search' && widget.getWidgetParameters) {
      return widget.getWidgetParameters(state, rest);
    }
    return widget.getWidgetSearchParameters(state, rest);
  }, initialSearchParameters);
}
function getLocalWidgetsRecommendParameters(widgets, widgetRecommendParametersOptions) {
  var initialRecommendParameters = widgetRecommendParametersOptions.initialRecommendParameters,
    rest = _objectWithoutProperties(widgetRecommendParametersOptions, _excluded2);
  return widgets.reduce(function (state, widget) {
    if (!(0, _utils.isIndexWidget)(widget) && widget.dependsOn === 'recommend' && widget.getWidgetParameters) {
      return widget.getWidgetParameters(state, rest);
    }
    return state;
  }, initialRecommendParameters);
}
function resetPageFromWidgets(widgets) {
  var indexWidgets = widgets.filter(_utils.isIndexWidget);
  if (indexWidgets.length === 0) {
    return;
  }
  indexWidgets.forEach(function (widget) {
    var widgetHelper = widget.getHelper();
    privateHelperSetState(widgetHelper, {
      state: widgetHelper.state.resetPage(),
      recommendState: widgetHelper.recommendState,
      isPageReset: true
    });
    resetPageFromWidgets(widget.getWidgets());
  });
}
function resolveScopedResultsFromWidgets(widgets) {
  var indexWidgets = widgets.filter(_utils.isIndexWidget);
  return indexWidgets.reduce(function (scopedResults, current) {
    return scopedResults.concat.apply(scopedResults, [{
      indexId: current.getIndexId(),
      results: current.getResults(),
      helper: current.getHelper()
    }].concat(_toConsumableArray(resolveScopedResultsFromWidgets(current.getWidgets()))));
  }, []);
}
var index = function index(widgetParams) {
  if (widgetParams === undefined || widgetParams.indexName === undefined && !widgetParams.EXPERIMENTAL_isolated) {
    throw new Error(withUsage('The `indexName` option is required.'));
  }

  // When isolated=true, we use an empty string as the default indexName.
  // This is intentional: isolated indices do not require a real index name.
  var _widgetParams$indexNa = widgetParams.indexName,
    indexName = _widgetParams$indexNa === void 0 ? '' : _widgetParams$indexNa,
    _widgetParams$indexId = widgetParams.indexId,
    indexId = _widgetParams$indexId === void 0 ? indexName : _widgetParams$indexId,
    _widgetParams$EXPERIM = widgetParams.EXPERIMENTAL_isolated,
    isolated = _widgetParams$EXPERIM === void 0 ? false : _widgetParams$EXPERIM;
  var localWidgets = [];
  var localUiState = {};
  var localInstantSearchInstance = null;
  var localParent = null;
  var helper = null;
  var derivedHelper = null;
  var lastValidSearchParameters = null;
  var hasRecommendWidget = false;
  var hasSearchWidget = false;
  return {
    $$type: 'ais.index',
    $$widgetType: 'ais.index',
    _isolated: isolated,
    getIndexName: function getIndexName() {
      return indexName;
    },
    getIndexId: function getIndexId() {
      return indexId;
    },
    getHelper: function getHelper() {
      return helper;
    },
    getResults: function getResults() {
      var _derivedHelper;
      if (!((_derivedHelper = derivedHelper) !== null && _derivedHelper !== void 0 && _derivedHelper.lastResults)) return null;

      // To make the UI optimistic, we patch the state to display to the current
      // one instead of the one associated with the latest results.
      // This means user-driven UI changes (e.g., checked checkbox) are reflected
      // immediately instead of waiting for Algolia to respond, regardless of
      // the status of the network request.
      derivedHelper.lastResults._state = helper.state;
      return derivedHelper.lastResults;
    },
    getResultsForWidget: function getResultsForWidget(widget) {
      var _helper;
      if (widget.dependsOn !== 'recommend' || (0, _utils.isIndexWidget)(widget) || widget.$$id === undefined) {
        return this.getResults();
      }
      if (!((_helper = helper) !== null && _helper !== void 0 && _helper.lastRecommendResults)) {
        return null;
      }
      return helper.lastRecommendResults[widget.$$id];
    },
    getPreviousState: function getPreviousState() {
      return lastValidSearchParameters;
    },
    getScopedResults: function getScopedResults() {
      var widgetParent = this.getParent();
      var widgetSiblings;
      if (widgetParent) {
        widgetSiblings = widgetParent.getWidgets();
      } else if (indexName.length === 0) {
        // The widget is the root but has no index name:
        // we resolve results from its children index widgets
        widgetSiblings = this.getWidgets();
      } else {
        // The widget is the root and has an index name:
        // we consider itself as the only sibling
        widgetSiblings = [this];
      }
      return resolveScopedResultsFromWidgets(widgetSiblings);
    },
    getParent: function getParent() {
      return isolated ? null : localParent;
    },
    createURL: function createURL(nextState) {
      if (typeof nextState === 'function') {
        return localInstantSearchInstance._createURL(_defineProperty({}, indexId, nextState(localUiState)));
      }
      return localInstantSearchInstance._createURL(_defineProperty({}, indexId, getLocalWidgetsUiState(localWidgets, {
        searchParameters: nextState,
        helper: helper
      })));
    },
    scheduleLocalSearch: (0, _utils.defer)(function () {
      if (isolated) {
        var _helper2;
        (_helper2 = helper) === null || _helper2 === void 0 ? void 0 : _helper2.search();
      }
    }),
    getWidgets: function getWidgets() {
      return localWidgets;
    },
    addWidgets: function addWidgets(widgets) {
      var _this = this;
      if (!Array.isArray(widgets)) {
        throw new Error(withUsage('The `addWidgets` method expects an array of widgets.'));
      }
      var flatWidgets = widgets.reduce(function (acc, w) {
        return acc.concat(Array.isArray(w) ? w : [w]);
      }, []);
      if (flatWidgets.some(function (widget) {
        return typeof widget.init !== 'function' && typeof widget.render !== 'function';
      })) {
        throw new Error(withUsage('The widget definition expects a `render` and/or an `init` method.'));
      }
      flatWidgets.forEach(function (widget) {
        widget.parent = _this;
        if ((0, _utils.isIndexWidget)(widget)) {
          return;
        }
        if (localInstantSearchInstance && widget.dependsOn === 'recommend') {
          localInstantSearchInstance._hasRecommendWidget = true;
        } else if (localInstantSearchInstance) {
          localInstantSearchInstance._hasSearchWidget = true;
        } else if (widget.dependsOn === 'recommend') {
          hasRecommendWidget = true;
        } else {
          hasSearchWidget = true;
        }
        (0, _addWidgetId.addWidgetId)(widget);
      });
      localWidgets = localWidgets.concat(flatWidgets);
      if (localInstantSearchInstance && Boolean(flatWidgets.length)) {
        privateHelperSetState(helper, {
          state: getLocalWidgetsSearchParameters(localWidgets, {
            uiState: localUiState,
            initialSearchParameters: helper.state
          }),
          recommendState: getLocalWidgetsRecommendParameters(localWidgets, {
            uiState: localUiState,
            initialRecommendParameters: helper.recommendState
          }),
          _uiState: localUiState
        });

        // We compute the render state before calling `init` in a separate loop
        // to construct the whole render state object that is then passed to
        // `init`.
        flatWidgets.forEach(function (widget) {
          if (widget.getRenderState) {
            var renderState = widget.getRenderState(localInstantSearchInstance.renderState[_this.getIndexId()] || {}, (0, _utils.createInitArgs)(localInstantSearchInstance, _this, localInstantSearchInstance._initialUiState));
            storeRenderState({
              renderState: renderState,
              instantSearchInstance: localInstantSearchInstance,
              parent: _this
            });
          }
        });
        flatWidgets.forEach(function (widget) {
          if (widget.init) {
            widget.init((0, _utils.createInitArgs)(localInstantSearchInstance, _this, localInstantSearchInstance._initialUiState));
          }
        });
        if (isolated) {
          this.scheduleLocalSearch();
        } else {
          localInstantSearchInstance.scheduleSearch();
        }
      }
      return this;
    },
    removeWidgets: function removeWidgets(widgets) {
      var _this2 = this;
      if (!Array.isArray(widgets)) {
        throw new Error(withUsage('The `removeWidgets` method expects an array of widgets.'));
      }
      var flatWidgets = widgets.reduce(function (acc, w) {
        return acc.concat(Array.isArray(w) ? w : [w]);
      }, []);
      if (flatWidgets.some(function (widget) {
        return typeof widget.dispose !== 'function';
      })) {
        throw new Error(withUsage('The widget definition expects a `dispose` method.'));
      }
      localWidgets = localWidgets.filter(function (widget) {
        return flatWidgets.indexOf(widget) === -1;
      });
      localWidgets.forEach(function (widget) {
        widget.parent = undefined;
        if ((0, _utils.isIndexWidget)(widget)) {
          return;
        }
        if (localInstantSearchInstance && widget.dependsOn === 'recommend') {
          localInstantSearchInstance._hasRecommendWidget = true;
        } else if (localInstantSearchInstance) {
          localInstantSearchInstance._hasSearchWidget = true;
        } else if (widget.dependsOn === 'recommend') {
          hasRecommendWidget = true;
        } else {
          hasSearchWidget = true;
        }
      });
      if (localInstantSearchInstance && Boolean(flatWidgets.length)) {
        var _flatWidgets$reduce = flatWidgets.reduce(function (states, widget) {
            // the `dispose` method exists at this point we already assert it
            var next = widget.dispose({
              helper: helper,
              state: states.cleanedSearchState,
              recommendState: states.cleanedRecommendState,
              parent: _this2
            });
            if (next instanceof _algoliasearchHelper.default.RecommendParameters) {
              states.cleanedRecommendState = next;
            } else if (next) {
              states.cleanedSearchState = next;
            }
            return states;
          }, {
            cleanedSearchState: helper.state,
            cleanedRecommendState: helper.recommendState
          }),
          cleanedSearchState = _flatWidgets$reduce.cleanedSearchState,
          cleanedRecommendState = _flatWidgets$reduce.cleanedRecommendState;
        var newState = localInstantSearchInstance.future.preserveSharedStateOnUnmount ? getLocalWidgetsSearchParameters(localWidgets, {
          uiState: localUiState,
          initialSearchParameters: new _algoliasearchHelper.default.SearchParameters({
            index: this.getIndexName()
          })
        }) : getLocalWidgetsSearchParameters(localWidgets, {
          uiState: getLocalWidgetsUiState(localWidgets, {
            searchParameters: cleanedSearchState,
            helper: helper
          }),
          initialSearchParameters: cleanedSearchState
        });
        localUiState = getLocalWidgetsUiState(localWidgets, {
          searchParameters: newState,
          helper: helper
        });
        helper.setState(newState);
        helper.recommendState = cleanedRecommendState;
        if (localWidgets.length) {
          if (isolated) {
            this.scheduleLocalSearch();
          } else {
            localInstantSearchInstance.scheduleSearch();
          }
        }
      }
      return this;
    },
    init: function init(_ref2) {
      var _this3 = this,
        _instantSearchInstanc;
      var instantSearchInstance = _ref2.instantSearchInstance,
        parent = _ref2.parent,
        uiState = _ref2.uiState;
      if (helper !== null) {
        // helper is already initialized, therefore we do not need to set up
        // any listeners
        return;
      }
      localInstantSearchInstance = instantSearchInstance;
      localParent = parent;
      localUiState = uiState[indexId] || {};

      // The `mainHelper` is already defined at this point. The instance is created
      // inside InstantSearch at the `start` method, which occurs before the `init`
      // step.
      var mainHelper = instantSearchInstance.mainHelper;
      var parameters = getLocalWidgetsSearchParameters(localWidgets, {
        uiState: localUiState,
        initialSearchParameters: new _algoliasearchHelper.default.SearchParameters({
          index: indexName
        })
      });
      var recommendParameters = getLocalWidgetsRecommendParameters(localWidgets, {
        uiState: localUiState,
        initialRecommendParameters: new _algoliasearchHelper.default.RecommendParameters()
      });

      // This Helper is only used for state management we do not care about the
      // `searchClient`. Only the "main" Helper created at the `InstantSearch`
      // level is aware of the client.
      helper = (0, _algoliasearchHelper.default)(mainHelper.getClient(), parameters.index, parameters);
      helper.recommendState = recommendParameters;

      // We forward the call to `search` to the "main" instance of the Helper
      // which is responsible for managing the queries (it's the only one that is
      // aware of the `searchClient`).
      helper.search = function () {
        if (isolated) {
          instantSearchInstance.status = 'loading';
          _this3.render({
            instantSearchInstance: instantSearchInstance
          });
          return instantSearchInstance.compositionID ? helper.searchWithComposition() : helper.searchOnlyWithDerivedHelpers();
        }
        if (instantSearchInstance.onStateChange) {
          instantSearchInstance.onStateChange({
            uiState: instantSearchInstance.mainIndex.getWidgetUiState({}),
            setUiState: function setUiState(nextState) {
              return instantSearchInstance.setUiState(nextState, false);
            }
          });

          // We don't trigger a search when controlled because it becomes the
          // responsibility of `setUiState`.
          return mainHelper;
        }
        return mainHelper.search();
      };
      helper.searchWithoutTriggeringOnStateChange = function () {
        return mainHelper.search();
      };
      var isolatedHelper = indexName ? helper : (0, _algoliasearchHelper.default)({}, '__empty_index__', {});
      var derivingHelper = isolated ? isolatedHelper : nearestIsolatedHelper(parent, mainHelper);
      derivedHelper = derivingHelper.derive(function () {
        return _utils.mergeSearchParameters.apply(void 0, [mainHelper.state].concat(_toConsumableArray((0, _utils.resolveSearchParameters)(_this3))));
      }, function () {
        return _this3.getHelper().recommendState;
      });
      var indexInitialResults = (_instantSearchInstanc = instantSearchInstance._initialResults) === null || _instantSearchInstanc === void 0 ? void 0 : _instantSearchInstanc[this.getIndexId()];
      if (indexInitialResults !== null && indexInitialResults !== void 0 && indexInitialResults.results) {
        // We restore the shape of the results provided to the instance to respect
        // the helper's structure.
        var results = new _algoliasearchHelper.default.SearchResults(new _algoliasearchHelper.default.SearchParameters(indexInitialResults.state), indexInitialResults.results);
        derivedHelper.lastResults = results;
        helper.lastResults = results;
      }
      if (indexInitialResults !== null && indexInitialResults !== void 0 && indexInitialResults.recommendResults) {
        var recommendResults = new _algoliasearchHelper.default.RecommendResults(new _algoliasearchHelper.default.RecommendParameters({
          params: indexInitialResults.recommendResults.params
        }), indexInitialResults.recommendResults.results);
        derivedHelper.lastRecommendResults = recommendResults;
        helper.lastRecommendResults = recommendResults;
      }

      // Subscribe to the Helper state changes for the page before widgets
      // are initialized. This behavior mimics the original one of the Helper.
      // It makes sense to replicate it at the `init` step. We have another
      // listener on `change` below, once `init` is done.
      helper.on('change', function (_ref3) {
        var isPageReset = _ref3.isPageReset;
        if (isPageReset) {
          resetPageFromWidgets(localWidgets);
        }
      });
      derivedHelper.on('search', function () {
        // The index does not manage the "staleness" of the search. This is the
        // responsibility of the main instance. It does not make sense to manage
        // it at the index level because it's either: all of them or none of them
        // that are stalled. The queries are performed into a single network request.
        instantSearchInstance.scheduleStalledRender();
        if (process.env.NODE_ENV === 'development') {
          (0, _utils.checkIndexUiState)({
            index: _this3,
            indexUiState: localUiState
          });
        }
      });
      derivedHelper.on('result', function (_ref4) {
        var results = _ref4.results;
        // The index does not render the results it schedules a new render
        // to let all the other indices emit their own results. It allows us to
        // run the render process in one pass.
        instantSearchInstance.scheduleRender();

        // the derived helper is the one which actually searches, but the helper
        // which is exposed e.g. via instance.helper, doesn't search, and thus
        // does not have access to lastResults, which it used to in pre-federated
        // search behavior.
        helper.lastResults = results;
        lastValidSearchParameters = results === null || results === void 0 ? void 0 : results._state;
      });

      // eslint-disable-next-line no-warning-comments
      // TODO: listen to "result" event when events for Recommend are implemented
      derivedHelper.on('recommend:result', function (_ref5) {
        var recommend = _ref5.recommend;
        // The index does not render the results it schedules a new render
        // to let all the other indices emit their own results. It allows us to
        // run the render process in one pass.
        instantSearchInstance.scheduleRender();

        // the derived helper is the one which actually searches, but the helper
        // which is exposed e.g. via instance.helper, doesn't search, and thus
        // does not have access to lastRecommendResults.
        helper.lastRecommendResults = recommend.results;
      });

      // We compute the render state before calling `init` in a separate loop
      // to construct the whole render state object that is then passed to
      // `init`.
      localWidgets.forEach(function (widget) {
        if (widget.getRenderState) {
          var renderState = widget.getRenderState(instantSearchInstance.renderState[_this3.getIndexId()] || {}, (0, _utils.createInitArgs)(instantSearchInstance, _this3, uiState));
          storeRenderState({
            renderState: renderState,
            instantSearchInstance: instantSearchInstance,
            parent: _this3
          });
        }
      });
      localWidgets.forEach(function (widget) {
        process.env.NODE_ENV === 'development' ? (0, _utils.warning)(
        // if it has NO getWidgetState or if it has getWidgetUiState, we don't warn
        // aka we warn if there's _only_ getWidgetState
        !widget.getWidgetState || Boolean(widget.getWidgetUiState), 'The `getWidgetState` method is renamed `getWidgetUiState` and will no longer exist under that name in InstantSearch.js 5.x. Please use `getWidgetUiState` instead.') : void 0;
        if (widget.init) {
          widget.init((0, _utils.createInitArgs)(instantSearchInstance, _this3, uiState));
        }
      });

      // Subscribe to the Helper state changes for the `uiState` once widgets
      // are initialized. Until the first render, state changes are part of the
      // configuration step. This is mainly for backward compatibility with custom
      // widgets. When the subscription happens before the `init` step, the (static)
      // configuration of the widget is pushed in the URL. That's what we want to avoid.
      // https://github.com/algolia/instantsearch/pull/994/commits/4a672ae3fd78809e213de0368549ef12e9dc9454
      helper.on('change', function (event) {
        var state = event.state;
        var _uiState = event._uiState;
        localUiState = getLocalWidgetsUiState(localWidgets, {
          searchParameters: state,
          helper: helper
        }, _uiState || {});

        // We don't trigger an internal change when controlled because it
        // becomes the responsibility of `setUiState`.
        if (!instantSearchInstance.onStateChange) {
          instantSearchInstance.onInternalStateChange();
        }
      });
      if (indexInitialResults) {
        // If there are initial results, we're not notified of the next results
        // because we don't trigger an initial search. We therefore need to directly
        // schedule a render that will render the results injected on the helper.
        instantSearchInstance.scheduleRender();
      }
      if (hasRecommendWidget) {
        instantSearchInstance._hasRecommendWidget = true;
      }
      if (hasSearchWidget) {
        instantSearchInstance._hasSearchWidget = true;
      }
    },
    render: function render(_ref6) {
      var _derivedHelper2,
        _this4 = this;
      var instantSearchInstance = _ref6.instantSearchInstance;
      // we can't attach a listener to the error event of search, as the error
      // then would no longer be thrown for global handlers.
      if (instantSearchInstance.status === 'error' && !instantSearchInstance.mainHelper.hasPendingRequests() && lastValidSearchParameters) {
        helper.setState(lastValidSearchParameters);
      }

      // We only render index widgets if there are no results.
      // This makes sure `render` is never called with `results` being `null`.
      // If it's an isolated index without an index name, we render all widgets,
      // as there are no results to display for the isolated index itself.
      var widgetsToRender = this.getResults() || (_derivedHelper2 = derivedHelper) !== null && _derivedHelper2 !== void 0 && _derivedHelper2.lastRecommendResults || isolated && !indexName ? localWidgets : localWidgets.filter(function (widget) {
        return widget.shouldRender;
      });
      widgetsToRender = widgetsToRender.filter(function (widget) {
        if (!widget.shouldRender) {
          return true;
        }
        return widget.shouldRender({
          instantSearchInstance: instantSearchInstance
        });
      });
      widgetsToRender.forEach(function (widget) {
        if (widget.getRenderState) {
          var renderState = widget.getRenderState(instantSearchInstance.renderState[_this4.getIndexId()] || {}, (0, _utils.createRenderArgs)(instantSearchInstance, _this4, widget));
          storeRenderState({
            renderState: renderState,
            instantSearchInstance: instantSearchInstance,
            parent: _this4
          });
        }
      });
      widgetsToRender.forEach(function (widget) {
        // At this point, all the variables used below are set. Both `helper`
        // and `derivedHelper` have been created at the `init` step. The attribute
        // `lastResults` might be `null` though. It's possible that a stalled render
        // happens before the result e.g with a dynamically added index the request might
        // be delayed. The render is triggered for the complete tree but some parts do
        // not have results yet.

        if (widget.render) {
          widget.render((0, _utils.createRenderArgs)(instantSearchInstance, _this4, widget));
        }
      });
    },
    dispose: function dispose() {
      var _this5 = this,
        _helper3,
        _derivedHelper3;
      localWidgets.forEach(function (widget) {
        if (widget.dispose && helper) {
          // The dispose function is always called once the instance is started
          // (it's an effect of `removeWidgets`). The index is initialized and
          // the Helper is available. We don't care about the return value of
          // `dispose` because the index is removed. We can't call `removeWidgets`
          // because we want to keep the widgets on the instance, to allow idempotent
          // operations on `add` & `remove`.
          widget.dispose({
            helper: helper,
            state: helper.state,
            recommendState: helper.recommendState,
            parent: _this5
          });
        }
      });
      localInstantSearchInstance = null;
      localParent = null;
      (_helper3 = helper) === null || _helper3 === void 0 ? void 0 : _helper3.removeAllListeners();
      helper = null;
      (_derivedHelper3 = derivedHelper) === null || _derivedHelper3 === void 0 ? void 0 : _derivedHelper3.detach();
      derivedHelper = null;
    },
    getWidgetUiState: function getWidgetUiState(uiState) {
      return localWidgets.filter(_utils.isIndexWidget).filter(function (w) {
        return !w._isolated;
      }).reduce(function (previousUiState, innerIndex) {
        return innerIndex.getWidgetUiState(previousUiState);
      }, _objectSpread(_objectSpread({}, uiState), {}, _defineProperty({}, indexId, _objectSpread(_objectSpread({}, uiState[indexId]), localUiState))));
    },
    getWidgetState: function getWidgetState(uiState) {
      process.env.NODE_ENV === 'development' ? (0, _utils.warning)(false, 'The `getWidgetState` method is renamed `getWidgetUiState` and will no longer exist under that name in InstantSearch.js 5.x. Please use `getWidgetUiState` instead.') : void 0;
      return this.getWidgetUiState(uiState);
    },
    getWidgetSearchParameters: function getWidgetSearchParameters(searchParameters, _ref7) {
      var uiState = _ref7.uiState;
      return getLocalWidgetsSearchParameters(localWidgets, {
        uiState: uiState,
        initialSearchParameters: searchParameters
      });
    },
    shouldRender: function shouldRender() {
      return true;
    },
    refreshUiState: function refreshUiState() {
      localUiState = getLocalWidgetsUiState(localWidgets, {
        searchParameters: this.getHelper().state,
        helper: this.getHelper()
      }, localUiState);
    },
    setIndexUiState: function setIndexUiState(indexUiState) {
      var nextIndexUiState = typeof indexUiState === 'function' ? indexUiState(localUiState) : indexUiState;
      localInstantSearchInstance.setUiState(function (state) {
        return _objectSpread(_objectSpread({}, state), {}, _defineProperty({}, indexId, nextIndexUiState));
      });
    }
  };
};
var _default = exports.default = index;
function storeRenderState(_ref8) {
  var renderState = _ref8.renderState,
    instantSearchInstance = _ref8.instantSearchInstance,
    parent = _ref8.parent;
  var parentIndexName = parent ? parent.getIndexId() : instantSearchInstance.mainIndex.getIndexId();
  instantSearchInstance.renderState = _objectSpread(_objectSpread({}, instantSearchInstance.renderState), {}, _defineProperty({}, parentIndexName, _objectSpread(_objectSpread({}, instantSearchInstance.renderState[parentIndexName]), renderState)));
}

/**
 * Walk up the parent chain to find the closest isolated index, or fall back to mainHelper
 */
function nearestIsolatedHelper(current, mainHelper) {
  while (current) {
    if (current._isolated) {
      return current.getHelper();
    }
    current = current.getParent();
  }
  return mainHelper;
}