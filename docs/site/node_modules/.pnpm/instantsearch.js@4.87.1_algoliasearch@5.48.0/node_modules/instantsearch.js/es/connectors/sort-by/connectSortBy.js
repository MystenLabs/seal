function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
import { checkRendering, createDocumentationMessageGenerator, find, warning, noop } from "../../lib/utils/index.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'sort-by',
  connector: true
});

/**
 * The **SortBy** connector provides the logic to build a custom widget that will display a
 * list of indices or sorting strategies. With Algolia, this is most commonly used for changing
 * ranking strategy. This allows a user to change how the hits are being sorted.
 *
 * This connector supports two sorting modes:
 * 1. **Index-based (traditional)**: Uses the `value` property to switch between different indices.
 *    This is the standard behavior for non-composition setups.
 *
 * 2. **Strategy-based (composition mode)**: Uses the `strategy` property to apply sorting strategies
 *    via the `sortBy` search parameter. This is only available when using Algolia Compositions.
 *
 * Items can mix both types in the same widget, allowing for flexible sorting options.
 */

function isStrategyItem(item) {
  return 'strategy' in item && item.strategy !== undefined;
}
function getItemValue(item) {
  if (isStrategyItem(item)) {
    return item.strategy;
  }
  return item.value;
}
function isValidStrategy(itemsLookup, value) {
  if (!value) return false;
  var item = itemsLookup[value];
  return item !== undefined && isStrategyItem(item);
}
var connectSortBy = function connectSortBy(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : noop;
  checkRendering(renderFn, withUsage());
  var connectorState = {};
  return function (widgetParams) {
    var _ref = widgetParams || {},
      items = _ref.items,
      _ref$transformItems = _ref.transformItems,
      transformItems = _ref$transformItems === void 0 ? function (x) {
        return x;
      } : _ref$transformItems;
    if (!Array.isArray(items)) {
      throw new Error(withUsage('The `items` option expects an array of objects.'));
    }
    var itemsLookup = {};
    items.forEach(function (item, index) {
      var hasValue = 'value' in item && item.value !== undefined;
      var hasStrategy = 'strategy' in item && item.strategy !== undefined;

      // Validate mutual exclusivity
      if (hasValue && hasStrategy) {
        throw new Error(withUsage("Item at index ".concat(index, " cannot have both \"value\" and \"strategy\" properties.")));
      }
      if (!hasValue && !hasStrategy) {
        throw new Error(withUsage("Item at index ".concat(index, " must have either a \"value\" or \"strategy\" property.")));
      }
      var itemValue = getItemValue(item);
      itemsLookup[itemValue] = item;
    });
    connectorState.itemsLookup = itemsLookup;
    return {
      $$type: 'ais.sortBy',
      init: function init(initOptions) {
        var instantSearchInstance = initOptions.instantSearchInstance;

        // Check if strategies are used outside composition mode
        var hasStrategyItems = items.some(function (item) {
          return 'strategy' in item && item.strategy;
        });
        if (hasStrategyItems && !instantSearchInstance.compositionID) {
          throw new Error(withUsage('Sorting strategies can only be used in composition mode. Please provide a "compositionID" to your InstantSearch instance.'));
        }
        var widgetRenderState = this.getWidgetRenderState(initOptions);
        var currentIndex = widgetRenderState.currentRefinement;
        var isCurrentIndexInItems = find(items, function (item) {
          return getItemValue(item) === currentIndex;
        });
        process.env.NODE_ENV === 'development' ? warning(isCurrentIndexInItems !== undefined, "The index named \"".concat(currentIndex, "\" is not listed in the `items` of `sortBy`.")) : void 0;
        renderFn(_objectSpread(_objectSpread({}, widgetRenderState), {}, {
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

        // Clear sortBy parameter if it was set
        if (connectorState.isUsingComposition && state.sortBy) {
          state = state.setQueryParameter('sortBy', undefined);
        }

        // Restore initial index if changed
        if (connectorState.initialValue && state.index !== connectorState.initialValue) {
          return state.setIndex(connectorState.initialValue);
        }
        return state;
      },
      getRenderState: function getRenderState(renderState, renderOptions) {
        return _objectSpread(_objectSpread({}, renderState), {}, {
          sortBy: this.getWidgetRenderState(renderOptions)
        });
      },
      getWidgetRenderState: function getWidgetRenderState(_ref3) {
        var results = _ref3.results,
          helper = _ref3.helper,
          state = _ref3.state,
          parent = _ref3.parent,
          instantSearchInstance = _ref3.instantSearchInstance;
        // Capture initial value (composition ID or main index)
        if (!connectorState.initialValue && parent) {
          connectorState.initialValue = parent.getIndexName();
        }

        // Create refine function if not exists
        if (!connectorState.refine) {
          // Cache composition mode status for lifecycle methods that don't have access to instantSearchInstance
          connectorState.isUsingComposition = Boolean(instantSearchInstance === null || instantSearchInstance === void 0 ? void 0 : instantSearchInstance.compositionID);
          connectorState.refine = function (value) {
            // O(1) lookup using the items lookup table
            var item = connectorState.itemsLookup[value];
            if (item && isStrategyItem(item)) {
              // Strategy-based: set sortBy parameter for composition API
              // The composition backend will interpret this and apply the sorting strategy
              helper.setQueryParameter('sortBy', item.strategy).search();
            } else {
              // Index-based: clear any existing sortBy parameter and switch to the new index
              // Clearing sortBy is critical when transitioning from strategy to index-based sorting
              helper.setQueryParameter('sortBy', undefined).setIndex(value).search();
            }
          };
        }

        // Transform items first (on original structure)
        var transformedItems = transformItems(items, {
          results: results
        });

        // Normalize items: all get a 'value' property for the render state
        var normalizedItems = transformedItems.map(function (item) {
          return {
            label: item.label,
            value: getItemValue(item)
          };
        });

        // Determine current refinement
        // In composition mode, prefer sortBy parameter if it corresponds to a valid strategy item
        // Otherwise use the index (for index-based items or when no valid strategy is active)
        var currentRefinement = connectorState.isUsingComposition && isValidStrategy(connectorState.itemsLookup, state.sortBy) ? state.sortBy : state.index;
        var hasNoResults = results ? results.nbHits === 0 : true;
        return {
          currentRefinement: currentRefinement,
          options: normalizedItems,
          refine: connectorState.refine,
          hasNoResults: hasNoResults,
          canRefine: !hasNoResults && items.length > 0,
          widgetParams: widgetParams
        };
      },
      getWidgetUiState: function getWidgetUiState(uiState, _ref4) {
        var searchParameters = _ref4.searchParameters;
        // In composition mode with an active strategy, use sortBy parameter
        // Otherwise use index-based behavior (traditional mode)
        var currentValue = connectorState.isUsingComposition && isValidStrategy(connectorState.itemsLookup, searchParameters.sortBy) ? searchParameters.sortBy : searchParameters.index;
        return _objectSpread(_objectSpread({}, uiState), {}, {
          sortBy: currentValue !== connectorState.initialValue ? currentValue : undefined
        });
      },
      getWidgetSearchParameters: function getWidgetSearchParameters(searchParameters, _ref5) {
        var uiState = _ref5.uiState;
        var sortByValue = uiState.sortBy || connectorState.initialValue || searchParameters.index;
        if (isValidStrategy(connectorState.itemsLookup, sortByValue)) {
          var item = connectorState.itemsLookup[sortByValue];
          // Strategy-based: set the sortBy parameter for composition API
          // The index remains as the compositionID
          return searchParameters.setQueryParameter('sortBy', item.strategy);
        }

        // Index-based: set the index parameter (traditional behavior)
        return searchParameters.setQueryParameter('index', sortByValue);
      }
    };
  };
};
export default connectSortBy;