function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _slicedToArray(r, e) { return _arrayWithHoles(r) || _iterableToArrayLimit(r, e) || _unsupportedIterableToArray(r, e) || _nonIterableRest(); }
function _nonIterableRest() { throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
function _iterableToArrayLimit(r, l) { var t = null == r ? null : "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"]; if (null != t) { var e, n, i, u, a = [], f = !0, o = !1; try { if (i = (t = t.call(r)).next, 0 === l) { if (Object(t) !== t) return; f = !1; } else for (; !(f = (e = i.call(t)).done) && (a.push(e.value), a.length !== l); f = !0); } catch (r) { o = !0, n = r; } finally { try { if (!f && null != t.return && (u = t.return(), Object(u) !== u)) return; } finally { if (o) throw n; } } return a; } }
function _arrayWithHoles(r) { if (Array.isArray(r)) return r; }
import { checkRendering, createDocumentationMessageGenerator, isFiniteNumber, find, noop } from "../../lib/utils/index.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'range-input',
  connector: true
}, {
  name: 'range-slider',
  connector: true
});
var $$type = 'ais.range';

// @MAJOR: potentially we should consolidate these types

function toPrecision(_ref) {
  var min = _ref.min,
    max = _ref.max,
    precision = _ref.precision;
  var pow = Math.pow(10, precision);
  return {
    min: min ? Math.floor(min * pow) / pow : min,
    max: max ? Math.ceil(max * pow) / pow : max
  };
}

/**
 * **Range** connector provides the logic to create custom widget that will let
 * the user refine results using a numeric range.
 *
 * This connectors provides a `refine()` function that accepts bounds. It will also provide
 * information about the min and max bounds for the current result set.
 */
var connectRange = function connectRange(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : noop;
  checkRendering(renderFn, withUsage());
  return function (widgetParams) {
    var _ref2 = widgetParams || {},
      _ref2$attribute = _ref2.attribute,
      attribute = _ref2$attribute === void 0 ? '' : _ref2$attribute,
      minBound = _ref2.min,
      maxBound = _ref2.max,
      _ref2$precision = _ref2.precision,
      precision = _ref2$precision === void 0 ? 0 : _ref2$precision;
    if (!attribute) {
      throw new Error(withUsage('The `attribute` option is required.'));
    }
    if (isFiniteNumber(minBound) && isFiniteNumber(maxBound) && minBound > maxBound) {
      throw new Error(withUsage("The `max` option can't be lower than `min`."));
    }
    var formatToNumber = function formatToNumber(v) {
      return Number(Number(v).toFixed(precision));
    };
    var rangeFormatter = {
      from: function from(v) {
        return v.toLocaleString();
      },
      to: function to(v) {
        return formatToNumber(v).toLocaleString();
      }
    };

    // eslint-disable-next-line complexity
    var getRefinedState = function getRefinedState(helper, currentRange, nextMin, nextMax) {
      var resolvedState = helper.state;
      var currentRangeMin = currentRange.min,
        currentRangeMax = currentRange.max;
      var _ref3 = resolvedState.getNumericRefinement(attribute, '>=') || [],
        _ref4 = _slicedToArray(_ref3, 1),
        min = _ref4[0];
      var _ref5 = resolvedState.getNumericRefinement(attribute, '<=') || [],
        _ref6 = _slicedToArray(_ref5, 1),
        max = _ref6[0];
      var isResetMin = nextMin === undefined || nextMin === '';
      var isResetMax = nextMax === undefined || nextMax === '';
      var _toPrecision = toPrecision({
          min: !isResetMin ? parseFloat(nextMin) : undefined,
          max: !isResetMax ? parseFloat(nextMax) : undefined,
          precision: precision
        }),
        nextMinAsNumber = _toPrecision.min,
        nextMaxAsNumber = _toPrecision.max;
      var newNextMin;
      if (!isFiniteNumber(minBound) && currentRangeMin === nextMinAsNumber) {
        newNextMin = undefined;
      } else if (isFiniteNumber(minBound) && isResetMin) {
        newNextMin = minBound;
      } else {
        newNextMin = nextMinAsNumber;
      }
      var newNextMax;
      if (!isFiniteNumber(maxBound) && currentRangeMax === nextMaxAsNumber) {
        newNextMax = undefined;
      } else if (isFiniteNumber(maxBound) && isResetMax) {
        newNextMax = maxBound;
      } else {
        newNextMax = nextMaxAsNumber;
      }
      var isResetNewNextMin = newNextMin === undefined;
      var isGreaterThanCurrentRange = isFiniteNumber(currentRangeMin) && currentRangeMin <= newNextMin;
      var isMinValid = isResetNewNextMin || isFiniteNumber(newNextMin) && (!isFiniteNumber(currentRangeMin) || isGreaterThanCurrentRange);
      var isResetNewNextMax = newNextMax === undefined;
      var isLowerThanRange = isFiniteNumber(newNextMax) && currentRangeMax >= newNextMax;
      var isMaxValid = isResetNewNextMax || isFiniteNumber(newNextMax) && (!isFiniteNumber(currentRangeMax) || isLowerThanRange);
      var hasMinChange = min !== newNextMin;
      var hasMaxChange = max !== newNextMax;
      if ((hasMinChange || hasMaxChange) && isMinValid && isMaxValid) {
        resolvedState = resolvedState.removeNumericRefinement(attribute);
        if (isFiniteNumber(newNextMin)) {
          resolvedState = resolvedState.addNumericRefinement(attribute, '>=', newNextMin);
        }
        if (isFiniteNumber(newNextMax)) {
          resolvedState = resolvedState.addNumericRefinement(attribute, '<=', newNextMax);
        }
        return resolvedState.resetPage();
      }
      return null;
    };
    var createSendEvent = function createSendEvent(instantSearchInstance) {
      return function () {
        if (arguments.length === 1) {
          instantSearchInstance.sendEventToInsights(arguments.length <= 0 ? undefined : arguments[0]);
          return;
        }
      };
    };
    function _getCurrentRange(stats) {
      var min;
      if (isFiniteNumber(minBound)) {
        min = minBound;
      } else if (isFiniteNumber(stats.min)) {
        min = stats.min;
      } else {
        min = 0;
      }
      var max;
      if (isFiniteNumber(maxBound)) {
        max = maxBound;
      } else if (isFiniteNumber(stats.max)) {
        max = stats.max;
      } else {
        max = 0;
      }
      return toPrecision({
        min: min,
        max: max,
        precision: precision
      });
    }
    function _getCurrentRefinement(helper) {
      var _ref7 = helper.getNumericRefinement(attribute, '>=') || [],
        _ref8 = _slicedToArray(_ref7, 1),
        minValue = _ref8[0];
      var _ref9 = helper.getNumericRefinement(attribute, '<=') || [],
        _ref0 = _slicedToArray(_ref9, 1),
        maxValue = _ref0[0];
      var min = isFiniteNumber(minValue) ? minValue : -Infinity;
      var max = isFiniteNumber(maxValue) ? maxValue : Infinity;
      return [min, max];
    }
    function _refine(helper, currentRange) {
      return function () {
        var _ref1 = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : [undefined, undefined],
          _ref10 = _slicedToArray(_ref1, 2),
          nextMin = _ref10[0],
          nextMax = _ref10[1];
        var refinedState = getRefinedState(helper, currentRange, nextMin, nextMax);
        if (refinedState) {
          helper.setState(refinedState).search();
        }
      };
    }
    return {
      $$type: $$type,
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
          range: _objectSpread(_objectSpread({}, renderState.range), {}, _defineProperty({}, attribute, this.getWidgetRenderState(renderOptions)))
        });
      },
      getWidgetRenderState: function getWidgetRenderState(_ref11) {
        var results = _ref11.results,
          helper = _ref11.helper,
          instantSearchInstance = _ref11.instantSearchInstance;
        var facetsFromResults = results && results.disjunctiveFacets || [];
        var facet = find(facetsFromResults, function (facetResult) {
          return facetResult.name === attribute;
        });
        var stats = facet && facet.stats || {
          min: undefined,
          max: undefined
        };
        var currentRange = _getCurrentRange(stats);
        var start = _getCurrentRefinement(helper);
        var refine;
        if (!results) {
          // On first render pass an empty range
          // to be able to bypass the validation
          // related to it
          refine = _refine(helper, {
            min: undefined,
            max: undefined
          });
        } else {
          refine = _refine(helper, currentRange);
        }
        return {
          refine: refine,
          canRefine: currentRange.min !== currentRange.max,
          format: rangeFormatter,
          range: currentRange,
          sendEvent: createSendEvent(instantSearchInstance),
          widgetParams: _objectSpread(_objectSpread({}, widgetParams), {}, {
            precision: precision
          }),
          start: start
        };
      },
      dispose: function dispose(_ref12) {
        var state = _ref12.state;
        unmountFn();
        return state.removeDisjunctiveFacet(attribute).removeNumericRefinement(attribute);
      },
      getWidgetUiState: function getWidgetUiState(uiState, _ref13) {
        var searchParameters = _ref13.searchParameters;
        var _searchParameters$get = searchParameters.getNumericRefinements(attribute),
          _searchParameters$get2 = _searchParameters$get['>='],
          min = _searchParameters$get2 === void 0 ? [] : _searchParameters$get2,
          _searchParameters$get3 = _searchParameters$get['<='],
          max = _searchParameters$get3 === void 0 ? [] : _searchParameters$get3;
        if (min.length === 0 && max.length === 0) {
          return uiState;
        }
        return _objectSpread(_objectSpread({}, uiState), {}, {
          range: _objectSpread(_objectSpread({}, uiState.range), {}, _defineProperty({}, attribute, "".concat(min, ":").concat(max)))
        });
      },
      getWidgetSearchParameters: function getWidgetSearchParameters(searchParameters, _ref14) {
        var uiState = _ref14.uiState;
        var widgetSearchParameters = searchParameters.addDisjunctiveFacet(attribute).setQueryParameters({
          numericRefinements: _objectSpread(_objectSpread({}, searchParameters.numericRefinements), {}, _defineProperty({}, attribute, {}))
        });
        if (isFiniteNumber(minBound)) {
          widgetSearchParameters = widgetSearchParameters.addNumericRefinement(attribute, '>=', minBound);
        }
        if (isFiniteNumber(maxBound)) {
          widgetSearchParameters = widgetSearchParameters.addNumericRefinement(attribute, '<=', maxBound);
        }
        var value = uiState.range && uiState.range[attribute];
        if (!value || value.indexOf(':') === -1) {
          return widgetSearchParameters;
        }
        var _value$split$map = value.split(':').map(parseFloat),
          _value$split$map2 = _slicedToArray(_value$split$map, 2),
          lowerBound = _value$split$map2[0],
          upperBound = _value$split$map2[1];
        if (isFiniteNumber(lowerBound) && (!isFiniteNumber(minBound) || minBound < lowerBound)) {
          widgetSearchParameters = widgetSearchParameters.removeNumericRefinement(attribute, '>=');
          widgetSearchParameters = widgetSearchParameters.addNumericRefinement(attribute, '>=', lowerBound);
        }
        if (isFiniteNumber(upperBound) && (!isFiniteNumber(maxBound) || upperBound < maxBound)) {
          widgetSearchParameters = widgetSearchParameters.removeNumericRefinement(attribute, '<=');
          widgetSearchParameters = widgetSearchParameters.addNumericRefinement(attribute, '<=', upperBound);
        }
        return widgetSearchParameters;
      }
    };
  };
};
export default connectRange;