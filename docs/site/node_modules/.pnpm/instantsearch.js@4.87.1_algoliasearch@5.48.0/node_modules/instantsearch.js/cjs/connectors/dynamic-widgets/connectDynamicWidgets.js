"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _utils = require("../../lib/utils");
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'dynamic-widgets',
  connector: true
});
var MAX_WILDCARD_FACETS = 20;
var connectDynamicWidgets = function connectDynamicWidgets(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : _utils.noop;
  (0, _utils.checkRendering)(renderFn, withUsage());
  return function (widgetParams) {
    var widgets = widgetParams.widgets,
      _widgetParams$maxValu = widgetParams.maxValuesPerFacet,
      maxValuesPerFacet = _widgetParams$maxValu === void 0 ? 20 : _widgetParams$maxValu,
      _widgetParams$facets = widgetParams.facets,
      facets = _widgetParams$facets === void 0 ? ['*'] : _widgetParams$facets,
      _widgetParams$transfo = widgetParams.transformItems,
      transformItems = _widgetParams$transfo === void 0 ? function (items) {
        return items;
      } : _widgetParams$transfo,
      fallbackWidget = widgetParams.fallbackWidget;
    if (!(widgets && Array.isArray(widgets) && widgets.every(function (widget) {
      return _typeof(widget) === 'object';
    }))) {
      throw new Error(withUsage('The `widgets` option expects an array of widgets.'));
    }
    if (!Array.isArray(facets)) {
      throw new Error(withUsage("The `facets` option only accepts an array of facets, you passed ".concat(JSON.stringify(facets))));
    }
    var localWidgets = new Map();
    return {
      $$type: 'ais.dynamicWidgets',
      init: function init(initOptions) {
        widgets.forEach(function (widget) {
          var attribute = (0, _utils.getWidgetAttribute)(widget, initOptions);
          localWidgets.set(attribute, {
            widget: widget,
            isMounted: false
          });
        });
        renderFn(_objectSpread(_objectSpread({}, this.getWidgetRenderState(initOptions)), {}, {
          instantSearchInstance: initOptions.instantSearchInstance
        }), true);
      },
      render: function render(renderOptions) {
        var parent = renderOptions.parent;
        var renderState = this.getWidgetRenderState(renderOptions);
        var widgetsToUnmount = [];
        var widgetsToMount = [];
        if (fallbackWidget) {
          renderState.attributesToRender.forEach(function (attribute) {
            if (!localWidgets.has(attribute)) {
              var widget = fallbackWidget({
                attribute: attribute
              });
              localWidgets.set(attribute, {
                widget: widget,
                isMounted: false
              });
            }
          });
        }
        localWidgets.forEach(function (_ref, attribute) {
          var widget = _ref.widget,
            isMounted = _ref.isMounted;
          var shouldMount = renderState.attributesToRender.indexOf(attribute) > -1;
          if (!isMounted && shouldMount) {
            widgetsToMount.push(widget);
            localWidgets.set(attribute, {
              widget: widget,
              isMounted: true
            });
          } else if (isMounted && !shouldMount) {
            widgetsToUnmount.push(widget);
            localWidgets.set(attribute, {
              widget: widget,
              isMounted: false
            });
          }
        });
        parent.addWidgets(widgetsToMount);
        // make sure this only happens after the regular render, otherwise it
        // happens too quick, since render is "deferred" for the next microtask,
        // so this needs to be a whole task later
        setTimeout(function () {
          return parent.removeWidgets(widgetsToUnmount);
        }, 0);
        renderFn(_objectSpread(_objectSpread({}, renderState), {}, {
          instantSearchInstance: renderOptions.instantSearchInstance
        }), false);
      },
      dispose: function dispose(_ref2) {
        var parent = _ref2.parent;
        var toRemove = [];
        localWidgets.forEach(function (_ref3) {
          var widget = _ref3.widget,
            isMounted = _ref3.isMounted;
          if (isMounted) {
            toRemove.push(widget);
          }
        });
        parent.removeWidgets(toRemove);
        unmountFn();
      },
      getWidgetSearchParameters: function getWidgetSearchParameters(state) {
        return facets.reduce(function (acc, curr) {
          return acc.addFacet(curr);
        }, state.setQueryParameters({
          maxValuesPerFacet: Math.max(maxValuesPerFacet || 0, state.maxValuesPerFacet || 0)
        }));
      },
      getRenderState: function getRenderState(renderState, renderOptions) {
        return _objectSpread(_objectSpread({}, renderState), {}, {
          dynamicWidgets: this.getWidgetRenderState(renderOptions)
        });
      },
      getWidgetRenderState: function getWidgetRenderState(_ref4) {
        var _results$renderingCon, _results$renderingCon2, _results$renderingCon3, _results$renderingCon4;
        var results = _ref4.results,
          state = _ref4.state;
        if (!results) {
          return {
            attributesToRender: [],
            widgetParams: widgetParams
          };
        }
        var attributesToRender = transformItems((_results$renderingCon = (_results$renderingCon2 = results.renderingContent) === null || _results$renderingCon2 === void 0 ? void 0 : (_results$renderingCon3 = _results$renderingCon2.facetOrdering) === null || _results$renderingCon3 === void 0 ? void 0 : (_results$renderingCon4 = _results$renderingCon3.facets) === null || _results$renderingCon4 === void 0 ? void 0 : _results$renderingCon4.order) !== null && _results$renderingCon !== void 0 ? _results$renderingCon : [], {
          results: results
        });
        if (!Array.isArray(attributesToRender)) {
          throw new Error(withUsage('The `transformItems` option expects a function that returns an Array.'));
        }
        process.env.NODE_ENV === 'development' ? (0, _utils.warning)(maxValuesPerFacet >= (state.maxValuesPerFacet || 0), "The maxValuesPerFacet set by dynamic widgets (".concat(maxValuesPerFacet, ") is smaller than one of the limits set by a widget (").concat(state.maxValuesPerFacet, "). This causes a mismatch in query parameters and thus an extra network request when that widget is mounted.")) : void 0;
        process.env.NODE_ENV === 'development' ? (0, _utils.warning)(attributesToRender.length <= MAX_WILDCARD_FACETS || widgetParams.facets !== undefined, "More than ".concat(MAX_WILDCARD_FACETS, " facets are requested to be displayed without explicitly setting which facets to retrieve. This could have a performance impact. Set \"facets\" to [] to do two smaller network requests, or explicitly to ['*'] to avoid this warning.")) : void 0;
        return {
          attributesToRender: attributesToRender,
          widgetParams: widgetParams
        };
      }
    };
  };
};
var _default = exports.default = connectDynamicWidgets;