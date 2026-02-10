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
import { checkRendering, escapeFacetValue, createDocumentationMessageGenerator, find, noop, toArray, warning } from "../../lib/utils/index.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'toggle-refinement',
  connector: true
});
var $$type = 'ais.toggleRefinement';
var createSendEvent = function createSendEvent(_ref) {
  var instantSearchInstance = _ref.instantSearchInstance,
    helper = _ref.helper,
    attribute = _ref.attribute,
    on = _ref.on;
  var sendEventForToggle = function sendEventForToggle() {
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }
    if (args.length === 1) {
      instantSearchInstance.sendEventToInsights(args[0]);
      return;
    }
    var isRefined = args[1],
      _args$ = args[2],
      eventName = _args$ === void 0 ? 'Filter Applied' : _args$;
    var _args$0$split = args[0].split(':'),
      _args$0$split2 = _slicedToArray(_args$0$split, 2),
      eventType = _args$0$split2[0],
      eventModifier = _args$0$split2[1];
    if (eventType !== 'click' || on === undefined) {
      return;
    }

    // only send an event when the refinement gets applied,
    // not when it gets removed
    if (!isRefined) {
      var _helper$lastResults;
      instantSearchInstance.sendEventToInsights({
        insightsMethod: 'clickedFilters',
        widgetType: $$type,
        eventType: eventType,
        eventModifier: eventModifier,
        payload: {
          eventName: eventName,
          index: ((_helper$lastResults = helper.lastResults) === null || _helper$lastResults === void 0 ? void 0 : _helper$lastResults.index) || helper.state.index,
          filters: on.map(function (value) {
            return "".concat(attribute, ":").concat(value);
          })
        },
        attribute: attribute
      });
    }
  };
  return sendEventForToggle;
};
/**
 * **Toggle** connector provides the logic to build a custom widget that will provide
 * an on/off filtering feature based on an attribute value or values.
 *
 * Two modes are implemented in the custom widget:
 *  - with or without the value filtered
 *  - switch between two values.
 */
var connectToggleRefinement = function connectToggleRefinement(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : noop;
  checkRendering(renderFn, withUsage());
  return function (widgetParams) {
    var _ref2 = widgetParams || {},
      attribute = _ref2.attribute,
      _ref2$on = _ref2.on,
      userOn = _ref2$on === void 0 ? true : _ref2$on,
      userOff = _ref2.off;
    if (!attribute) {
      throw new Error(withUsage('The `attribute` option is required.'));
    }
    var hasAnOffValue = userOff !== undefined;
    // even though facet values can be numbers and boolean,
    // the helper methods only accept string in the type
    var on = toArray(userOn).map(escapeFacetValue);
    var off = hasAnOffValue ? toArray(userOff).map(escapeFacetValue) : undefined;
    var sendEvent;
    var toggleRefinementFactory = function toggleRefinementFactory(helper) {
      return function () {
        var _ref3 = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {
            isRefined: false
          },
          isRefined = _ref3.isRefined;
        if (!isRefined) {
          sendEvent('click:internal', isRefined);
          if (hasAnOffValue) {
            off.forEach(function (v) {
              return helper.removeDisjunctiveFacetRefinement(attribute, v);
            });
          }
          on.forEach(function (v) {
            return helper.addDisjunctiveFacetRefinement(attribute, v);
          });
        } else {
          on.forEach(function (v) {
            return helper.removeDisjunctiveFacetRefinement(attribute, v);
          });
          if (hasAnOffValue) {
            off.forEach(function (v) {
              return helper.addDisjunctiveFacetRefinement(attribute, v);
            });
          }
        }
        helper.search();
      };
    };
    var connectorState = {
      createURLFactory: function createURLFactory(isRefined, _ref4) {
        var state = _ref4.state,
          createURL = _ref4.createURL,
          getWidgetUiState = _ref4.getWidgetUiState,
          helper = _ref4.helper;
        return function () {
          state = state.resetPage();
          var valuesToRemove = isRefined ? on : off;
          if (valuesToRemove) {
            valuesToRemove.forEach(function (v) {
              state = state.removeDisjunctiveFacetRefinement(attribute, v);
            });
          }
          var valuesToAdd = isRefined ? off : on;
          if (valuesToAdd) {
            valuesToAdd.forEach(function (v) {
              state = state.addDisjunctiveFacetRefinement(attribute, v);
            });
          }
          return createURL(function (uiState) {
            return getWidgetUiState(uiState, {
              searchParameters: state,
              helper: helper
            });
          });
        };
      }
    };
    return {
      $$type: $$type,
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
      dispose: function dispose(_ref5) {
        var state = _ref5.state;
        unmountFn();
        return state.removeDisjunctiveFacet(attribute);
      },
      getRenderState: function getRenderState(renderState, renderOptions) {
        return _objectSpread(_objectSpread({}, renderState), {}, {
          toggleRefinement: _objectSpread(_objectSpread({}, renderState.toggleRefinement), {}, _defineProperty({}, attribute, this.getWidgetRenderState(renderOptions)))
        });
      },
      getWidgetRenderState: function getWidgetRenderState(_ref6) {
        var state = _ref6.state,
          helper = _ref6.helper,
          results = _ref6.results,
          createURL = _ref6.createURL,
          instantSearchInstance = _ref6.instantSearchInstance;
        var isRefined = results ? on.every(function (v) {
          return state.isDisjunctiveFacetRefined(attribute, v);
        }) : on.every(function (v) {
          return state.isDisjunctiveFacetRefined(attribute, v);
        });
        var onFacetValue = {
          isRefined: isRefined,
          count: 0
        };
        var offFacetValue = {
          isRefined: hasAnOffValue && !isRefined,
          count: 0
        };
        if (results) {
          var offValue = toArray(off || false);
          var allFacetValues = results.getFacetValues(attribute, {}) || [];
          var onData = on.map(function (v) {
            return find(allFacetValues, function (_ref7) {
              var escapedValue = _ref7.escapedValue;
              return escapedValue === escapeFacetValue(String(v));
            });
          }).filter(function (v) {
            return v !== undefined;
          });
          var offData = hasAnOffValue ? offValue.map(function (v) {
            return find(allFacetValues, function (_ref8) {
              var escapedValue = _ref8.escapedValue;
              return escapedValue === escapeFacetValue(String(v));
            });
          }).filter(function (v) {
            return v !== undefined;
          }) : [];
          onFacetValue = {
            isRefined: onData.length ? onData.every(function (v) {
              return v.isRefined;
            }) : false,
            count: onData.reduce(function (acc, v) {
              return acc + v.count;
            }, 0) || null
          };
          offFacetValue = {
            isRefined: offData.length ? offData.every(function (v) {
              return v.isRefined;
            }) : false,
            count: offData.reduce(function (acc, v) {
              return acc + v.count;
            }, 0) || allFacetValues.reduce(function (total, _ref9) {
              var count = _ref9.count;
              return total + count;
            }, 0)
          };
        }
        if (!sendEvent) {
          sendEvent = createSendEvent({
            instantSearchInstance: instantSearchInstance,
            attribute: attribute,
            on: on,
            helper: helper
          });
        }
        var nextRefinement = isRefined ? offFacetValue : onFacetValue;
        return {
          value: {
            name: attribute,
            isRefined: isRefined,
            count: results ? nextRefinement.count : null,
            onFacetValue: onFacetValue,
            offFacetValue: offFacetValue
          },
          createURL: connectorState.createURLFactory(isRefined, {
            state: state,
            createURL: createURL,
            helper: helper,
            getWidgetUiState: this.getWidgetUiState
          }),
          sendEvent: sendEvent,
          canRefine: Boolean(results ? nextRefinement.count : null),
          refine: toggleRefinementFactory(helper),
          widgetParams: widgetParams
        };
      },
      getWidgetUiState: function getWidgetUiState(uiState, _ref0) {
        var searchParameters = _ref0.searchParameters;
        var isRefined = on && on.every(function (v) {
          return searchParameters.isDisjunctiveFacetRefined(attribute, v);
        });
        if (!isRefined) {
          var _uiState$toggle;
          // This needs to be done in the case `uiState` comes from `createURL`
          (_uiState$toggle = uiState.toggle) === null || _uiState$toggle === void 0 ? true : delete _uiState$toggle[attribute];
          return uiState;
        }
        return _objectSpread(_objectSpread({}, uiState), {}, {
          toggle: _objectSpread(_objectSpread({}, uiState.toggle), {}, _defineProperty({}, attribute, isRefined))
        });
      },
      getWidgetSearchParameters: function getWidgetSearchParameters(searchParameters, _ref1) {
        var uiState = _ref1.uiState;
        if (searchParameters.isHierarchicalFacet(attribute) || searchParameters.isConjunctiveFacet(attribute)) {
          process.env.NODE_ENV === 'development' ? warning(false, "ToggleRefinement: Attribute \"".concat(attribute, "\" is already used by another widget of a different type.\nAs this is not supported, please make sure to remove this other widget or this ToggleRefinement widget will not work at all.")) : void 0;
          return searchParameters;
        }
        var withFacetConfiguration = searchParameters.addDisjunctiveFacet(attribute).removeDisjunctiveFacetRefinement(attribute);
        var isRefined = Boolean(uiState.toggle && uiState.toggle[attribute]);
        if (isRefined) {
          if (on) {
            on.forEach(function (v) {
              withFacetConfiguration = withFacetConfiguration.addDisjunctiveFacetRefinement(attribute, v);
            });
          }
          return withFacetConfiguration;
        }

        // It's not refined with an `off` value
        if (hasAnOffValue) {
          if (off) {
            off.forEach(function (v) {
              withFacetConfiguration = withFacetConfiguration.addDisjunctiveFacetRefinement(attribute, v);
            });
          }
          return withFacetConfiguration;
        }

        // It's not refined without an `off` value
        return withFacetConfiguration.setQueryParameters({
          disjunctiveFacetsRefinements: _objectSpread(_objectSpread({}, searchParameters.disjunctiveFacetsRefinements), {}, _defineProperty({}, attribute, []))
        });
      }
    };
  };
};
export default connectToggleRefinement;