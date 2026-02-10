function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
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
import { checkRendering, createDocumentationMessageGenerator, warning, getRefinements, isEqual, noop } from "../../lib/utils/index.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'query-rules',
  connector: true
});
function hasStateRefinements(state) {
  return [state.disjunctiveFacetsRefinements, state.facetsRefinements, state.hierarchicalFacetsRefinements, state.numericRefinements].some(function (refinement) {
    return Boolean(refinement && Object.keys(refinement).length > 0);
  });
}

// A context rule must consist only of alphanumeric characters, hyphens, and underscores.
// See https://www.algolia.com/doc/guides/managing-results/refine-results/merchandising-and-promoting/in-depth/implementing-query-rules/#context
function escapeRuleContext(ruleName) {
  return ruleName.replace(/[^a-z0-9-_]+/gi, '_');
}
function getRuleContextsFromTrackedFilters(_ref) {
  var helper = _ref.helper,
    sharedHelperState = _ref.sharedHelperState,
    trackedFilters = _ref.trackedFilters;
  var ruleContexts = Object.keys(trackedFilters).reduce(function (facets, facetName) {
    var facetRefinements = getRefinements(helper.lastResults || {}, sharedHelperState, true).filter(function (refinement) {
      return refinement.attribute === facetName;
    }).map(function (refinement) {
      return refinement.numericValue || refinement.name;
    });
    var getTrackedFacetValues = trackedFilters[facetName];
    var trackedFacetValues = getTrackedFacetValues(facetRefinements);
    return [].concat(_toConsumableArray(facets), _toConsumableArray(facetRefinements.filter(function (facetRefinement) {
      return trackedFacetValues.includes(facetRefinement);
    }).map(function (facetValue) {
      return escapeRuleContext("ais-".concat(facetName, "-").concat(facetValue));
    })));
  }, []);
  return ruleContexts;
}
function applyRuleContexts(event) {
  var helper = this.helper,
    initialRuleContexts = this.initialRuleContexts,
    trackedFilters = this.trackedFilters,
    transformRuleContexts = this.transformRuleContexts;
  var sharedHelperState = event.state;
  var previousRuleContexts = sharedHelperState.ruleContexts || [];
  var newRuleContexts = getRuleContextsFromTrackedFilters({
    helper: helper,
    sharedHelperState: sharedHelperState,
    trackedFilters: trackedFilters
  });
  var nextRuleContexts = [].concat(_toConsumableArray(initialRuleContexts), _toConsumableArray(newRuleContexts));
  process.env.NODE_ENV === 'development' ? warning(nextRuleContexts.length <= 10, "\nThe maximum number of `ruleContexts` is 10. They have been sliced to that limit.\nConsider using `transformRuleContexts` to minimize the number of rules sent to Algolia.\n") : void 0;
  var ruleContexts = transformRuleContexts(nextRuleContexts).slice(0, 10);
  if (!isEqual(previousRuleContexts, ruleContexts)) {
    helper.overrideStateWithoutTriggeringChangeEvent(_objectSpread(_objectSpread({}, sharedHelperState), {}, {
      ruleContexts: ruleContexts
    }));
  }
}
var connectQueryRules = function connectQueryRules(_render) {
  var unmount = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : noop;
  checkRendering(_render, withUsage());
  return function (widgetParams) {
    var _ref2 = widgetParams || {},
      _ref2$trackedFilters = _ref2.trackedFilters,
      trackedFilters = _ref2$trackedFilters === void 0 ? {} : _ref2$trackedFilters,
      _ref2$transformRuleCo = _ref2.transformRuleContexts,
      transformRuleContexts = _ref2$transformRuleCo === void 0 ? function (rules) {
        return rules;
      } : _ref2$transformRuleCo,
      _ref2$transformItems = _ref2.transformItems,
      transformItems = _ref2$transformItems === void 0 ? function (items) {
        return items;
      } : _ref2$transformItems;
    Object.keys(trackedFilters).forEach(function (facetName) {
      if (typeof trackedFilters[facetName] !== 'function') {
        throw new Error(withUsage("'The \"".concat(facetName, "\" filter value in the `trackedFilters` option expects a function.")));
      }
    });
    var hasTrackedFilters = Object.keys(trackedFilters).length > 0;

    // We store the initial rule contexts applied before creating the widget
    // so that we do not override them with the rules created from `trackedFilters`.
    var initialRuleContexts = [];
    var onHelperChange;
    return {
      $$type: 'ais.queryRules',
      init: function init(initOptions) {
        var helper = initOptions.helper,
          state = initOptions.state,
          instantSearchInstance = initOptions.instantSearchInstance;
        initialRuleContexts = state.ruleContexts || [];
        onHelperChange = applyRuleContexts.bind({
          helper: helper,
          initialRuleContexts: initialRuleContexts,
          trackedFilters: trackedFilters,
          transformRuleContexts: transformRuleContexts
        });
        if (hasTrackedFilters) {
          // We need to apply the `ruleContexts` based on the `trackedFilters`
          // before the helper changes state in some cases:
          //   - Some filters are applied on the first load (e.g. using `configure`)
          //   - The `transformRuleContexts` option sets initial `ruleContexts`.
          if (hasStateRefinements(state) || Boolean(widgetParams.transformRuleContexts)) {
            onHelperChange({
              state: state
            });
          }

          // We track every change in the helper to override its state and add
          // any `ruleContexts` needed based on the `trackedFilters`.
          helper.on('change', onHelperChange);
        }
        _render(_objectSpread(_objectSpread({}, this.getWidgetRenderState(initOptions)), {}, {
          instantSearchInstance: instantSearchInstance
        }), true);
      },
      render: function render(renderOptions) {
        var instantSearchInstance = renderOptions.instantSearchInstance;
        _render(_objectSpread(_objectSpread({}, this.getWidgetRenderState(renderOptions)), {}, {
          instantSearchInstance: instantSearchInstance
        }), false);
      },
      getWidgetRenderState: function getWidgetRenderState(_ref3) {
        var results = _ref3.results;
        var _ref4 = results || {},
          _ref4$userData = _ref4.userData,
          userData = _ref4$userData === void 0 ? [] : _ref4$userData;
        var items = transformItems(userData, {
          results: results
        });
        return {
          items: items,
          widgetParams: widgetParams
        };
      },
      getRenderState: function getRenderState(renderState, renderOptions) {
        return _objectSpread(_objectSpread({}, renderState), {}, {
          queryRules: this.getWidgetRenderState(renderOptions)
        });
      },
      dispose: function dispose(_ref5) {
        var helper = _ref5.helper,
          state = _ref5.state;
        unmount();
        if (hasTrackedFilters) {
          helper.removeListener('change', onHelperChange);
          return state.setQueryParameter('ruleContexts', initialRuleContexts);
        }
        return state;
      }
    };
  };
};
export default connectQueryRules;