"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _utils = require("../../lib/utils");
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function _createForOfIteratorHelper(r, e) { var t = "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"]; if (!t) { if (Array.isArray(r) || (t = _unsupportedIterableToArray(r)) || e && r && "number" == typeof r.length) { t && (r = t); var _n = 0, F = function F() {}; return { s: F, n: function n() { return _n >= r.length ? { done: !0 } : { done: !1, value: r[_n++] }; }, e: function e(r) { throw r; }, f: F }; } throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); } var o, a = !0, u = !1; return { s: function s() { t = t.call(r); }, n: function n() { var r = t.next(); return a = r.done, r; }, e: function e(r) { u = !0, o = r; }, f: function f() { try { a || null == t.return || t.return(); } finally { if (u) throw o; } } }; }
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
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'numeric-menu',
  connector: true
});
var $$type = 'ais.numericMenu';
var createSendEvent = function createSendEvent(_ref) {
  var instantSearchInstance = _ref.instantSearchInstance;
  return function () {
    if (arguments.length === 1) {
      instantSearchInstance.sendEventToInsights(arguments.length <= 0 ? undefined : arguments[0]);
      return;
    }
  };
};
var connectNumericMenu = function connectNumericMenu(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : _utils.noop;
  (0, _utils.checkRendering)(renderFn, withUsage());
  return function (widgetParams) {
    var _ref2 = widgetParams || {},
      _ref2$attribute = _ref2.attribute,
      attribute = _ref2$attribute === void 0 ? '' : _ref2$attribute,
      _ref2$items = _ref2.items,
      items = _ref2$items === void 0 ? [] : _ref2$items,
      _ref2$transformItems = _ref2.transformItems,
      transformItems = _ref2$transformItems === void 0 ? function (item) {
        return item;
      } : _ref2$transformItems;
    if (attribute === '') {
      throw new Error(withUsage('The `attribute` option is required.'));
    }
    if (!items || items.length === 0) {
      throw new Error(withUsage('The `items` option expects an array of objects.'));
    }
    var prepareItems = function prepareItems(state) {
      return items.map(function (_ref3) {
        var start = _ref3.start,
          end = _ref3.end,
          label = _ref3.label;
        return {
          label: label,
          value: encodeURI(JSON.stringify({
            start: start,
            end: end
          })),
          isRefined: isRefined(state, attribute, {
            start: start,
            end: end,
            label: label
          })
        };
      });
    };
    var connectorState = {};
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
      dispose: function dispose(_ref4) {
        var state = _ref4.state;
        unmountFn();
        return state.removeNumericRefinement(attribute);
      },
      getWidgetUiState: function getWidgetUiState(uiState, _ref5) {
        var searchParameters = _ref5.searchParameters;
        var values = searchParameters.getNumericRefinements(attribute);
        var equal = values['='] && values['='][0];
        if (equal || equal === 0) {
          return _objectSpread(_objectSpread({}, uiState), {}, {
            numericMenu: _objectSpread(_objectSpread({}, uiState.numericMenu), {}, _defineProperty({}, attribute, "".concat(values['='])))
          });
        }
        var min = values['>='] && values['>='][0] || '';
        var max = values['<='] && values['<='][0] || '';
        return removeEmptyRefinementsFromUiState(_objectSpread(_objectSpread({}, uiState), {}, {
          numericMenu: _objectSpread(_objectSpread({}, uiState.numericMenu), {}, _defineProperty({}, attribute, "".concat(min, ":").concat(max)))
        }), attribute);
      },
      getWidgetSearchParameters: function getWidgetSearchParameters(searchParameters, _ref6) {
        var uiState = _ref6.uiState;
        var value = uiState.numericMenu && uiState.numericMenu[attribute];
        var withoutRefinements = searchParameters.setQueryParameters({
          numericRefinements: _objectSpread(_objectSpread({}, searchParameters.numericRefinements), {}, _defineProperty({}, attribute, {}))
        });
        if (!value) {
          return withoutRefinements;
        }
        var isExact = value.indexOf(':') === -1;
        if (isExact) {
          return withoutRefinements.addNumericRefinement(attribute, '=', Number(value));
        }
        var _value$split$map = value.split(':').map(parseFloat),
          _value$split$map2 = _slicedToArray(_value$split$map, 2),
          min = _value$split$map2[0],
          max = _value$split$map2[1];
        var withMinRefinement = (0, _utils.isFiniteNumber)(min) ? withoutRefinements.addNumericRefinement(attribute, '>=', min) : withoutRefinements;
        var withMaxRefinement = (0, _utils.isFiniteNumber)(max) ? withMinRefinement.addNumericRefinement(attribute, '<=', max) : withMinRefinement;
        return withMaxRefinement;
      },
      getRenderState: function getRenderState(renderState, renderOptions) {
        return _objectSpread(_objectSpread({}, renderState), {}, {
          numericMenu: _objectSpread(_objectSpread({}, renderState.numericMenu), {}, _defineProperty({}, attribute, this.getWidgetRenderState(renderOptions)))
        });
      },
      getWidgetRenderState: function getWidgetRenderState(_ref7) {
        var _this = this;
        var results = _ref7.results,
          state = _ref7.state,
          instantSearchInstance = _ref7.instantSearchInstance,
          helper = _ref7.helper,
          createURL = _ref7.createURL;
        if (!connectorState.refine) {
          connectorState.refine = function (facetValue) {
            var refinedState = getRefinedState(helper.state, attribute, facetValue);
            connectorState.sendEvent('click:internal', facetValue);
            helper.setState(refinedState).search();
          };
        }
        if (!connectorState.createURL) {
          connectorState.createURL = function (newState) {
            return function (facetValue) {
              return createURL(function (uiState) {
                return _this.getWidgetUiState(uiState, {
                  searchParameters: getRefinedState(newState, attribute, facetValue),
                  helper: helper
                });
              });
            };
          };
        }
        if (!connectorState.sendEvent) {
          connectorState.sendEvent = createSendEvent({
            instantSearchInstance: instantSearchInstance
          });
        }
        var hasNoResults = results ? results.nbHits === 0 : true;
        var preparedItems = prepareItems(state);
        var allIsSelected = true;
        // @TODO avoid for..of for polyfill reasons
        // eslint-disable-next-line no-restricted-syntax
        var _iterator = _createForOfIteratorHelper(preparedItems),
          _step;
        try {
          for (_iterator.s(); !(_step = _iterator.n()).done;) {
            var item = _step.value;
            if (item.isRefined && decodeURI(item.value) !== '{}') {
              allIsSelected = false;
              break;
            }
          }
        } catch (err) {
          _iterator.e(err);
        } finally {
          _iterator.f();
        }
        return {
          createURL: connectorState.createURL(state),
          items: transformItems(preparedItems, {
            results: results
          }),
          hasNoResults: hasNoResults,
          canRefine: !(hasNoResults && allIsSelected),
          refine: connectorState.refine,
          sendEvent: connectorState.sendEvent,
          widgetParams: widgetParams
        };
      }
    };
  };
};
function isRefined(state, attribute, option) {
  // @TODO: same as another spot, why is this mixing arrays & elements?
  var currentRefinements = state.getNumericRefinements(attribute);
  if (option.start !== undefined && option.end !== undefined) {
    if (option.start === option.end) {
      return hasNumericRefinement(currentRefinements, '=', option.start);
    } else {
      return hasNumericRefinement(currentRefinements, '>=', option.start) && hasNumericRefinement(currentRefinements, '<=', option.end);
    }
  }
  if (option.start !== undefined) {
    return hasNumericRefinement(currentRefinements, '>=', option.start);
  }
  if (option.end !== undefined) {
    return hasNumericRefinement(currentRefinements, '<=', option.end);
  }
  if (option.start === undefined && option.end === undefined) {
    return Object.keys(currentRefinements).every(function (operator) {
      return (currentRefinements[operator] || []).length === 0;
    });
  }
  return false;
}
function getRefinedState(state, attribute, facetValue) {
  var resolvedState = state;
  var refinedOption = JSON.parse(decodeURI(facetValue));

  // @TODO: why is array / element mixed here & hasRefinements; seems wrong?
  var currentRefinements = resolvedState.getNumericRefinements(attribute);
  if (refinedOption.start === undefined && refinedOption.end === undefined) {
    return resolvedState.removeNumericRefinement(attribute);
  }
  if (!isRefined(resolvedState, attribute, refinedOption)) {
    resolvedState = resolvedState.removeNumericRefinement(attribute);
  }
  if (refinedOption.start !== undefined && refinedOption.end !== undefined) {
    if (refinedOption.start > refinedOption.end) {
      throw new Error('option.start should be > to option.end');
    }
    if (refinedOption.start === refinedOption.end) {
      if (hasNumericRefinement(currentRefinements, '=', refinedOption.start)) {
        resolvedState = resolvedState.removeNumericRefinement(attribute, '=', refinedOption.start);
      } else {
        resolvedState = resolvedState.addNumericRefinement(attribute, '=', refinedOption.start);
      }
      return resolvedState;
    }
  }
  if (refinedOption.start !== undefined) {
    if (hasNumericRefinement(currentRefinements, '>=', refinedOption.start)) {
      resolvedState = resolvedState.removeNumericRefinement(attribute, '>=', refinedOption.start);
    }
    resolvedState = resolvedState.addNumericRefinement(attribute, '>=', refinedOption.start);
  }
  if (refinedOption.end !== undefined) {
    if (hasNumericRefinement(currentRefinements, '<=', refinedOption.end)) {
      resolvedState = resolvedState.removeNumericRefinement(attribute, '<=', refinedOption.end);
    }
    resolvedState = resolvedState.addNumericRefinement(attribute, '<=', refinedOption.end);
  }
  if (typeof resolvedState.page === 'number') {
    resolvedState.page = 0;
  }
  return resolvedState;
}
function hasNumericRefinement(currentRefinements, operator, value) {
  return currentRefinements[operator] !== undefined && currentRefinements[operator].includes(value);
}
function removeEmptyRefinementsFromUiState(indexUiState, attribute) {
  if (!indexUiState.numericMenu) {
    return indexUiState;
  }
  if (indexUiState.numericMenu[attribute] === ':') {
    delete indexUiState.numericMenu[attribute];
  }
  if (Object.keys(indexUiState.numericMenu).length === 0) {
    delete indexUiState.numericMenu;
  }
  return indexUiState;
}
var _default = exports.default = connectNumericMenu;