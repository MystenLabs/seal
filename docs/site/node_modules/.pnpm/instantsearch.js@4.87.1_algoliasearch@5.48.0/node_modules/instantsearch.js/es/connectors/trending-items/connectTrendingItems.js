function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
import { createDocumentationMessageGenerator, checkRendering, noop, escapeHits, TAG_PLACEHOLDER, getObjectType, createSendEventForHits, addAbsolutePosition, addQueryID } from "../../lib/utils/index.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'trending-items',
  connector: true
});
export default (function connectTrendingItems(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : noop;
  checkRendering(renderFn, withUsage());
  return function (widgetParams) {
    var _ref = widgetParams || {},
      facetName = _ref.facetName,
      facetValue = _ref.facetValue,
      limit = _ref.limit,
      threshold = _ref.threshold,
      fallbackParameters = _ref.fallbackParameters,
      queryParameters = _ref.queryParameters,
      _ref$escapeHTML = _ref.escapeHTML,
      escapeHTML = _ref$escapeHTML === void 0 ? true : _ref$escapeHTML,
      _ref$transformItems = _ref.transformItems,
      transformItems = _ref$transformItems === void 0 ? function (items) {
        return items;
      } : _ref$transformItems;
    if (facetName && !facetValue || !facetName && facetValue) {
      throw new Error(withUsage("When you provide facetName (received type ".concat(getObjectType(facetName), "), you must also provide facetValue (received type ").concat(getObjectType(facetValue), ").")));
    }
    var sendEvent;
    return {
      dependsOn: 'recommend',
      $$type: 'ais.trendingItems',
      init: function init(initOptions) {
        renderFn(_objectSpread(_objectSpread({}, this.getWidgetRenderState(initOptions)), {}, {
          instantSearchInstance: initOptions.instantSearchInstance
        }), true);
      },
      render: function render(renderOptions) {
        var renderState = this.getWidgetRenderState(renderOptions);
        renderFn(_objectSpread(_objectSpread({}, renderState), {}, {
          instantSearchInstance: renderOptions.instantSearchInstance
        }), false);
      },
      getRenderState: function getRenderState(renderState) {
        return renderState;
      },
      getWidgetRenderState: function getWidgetRenderState(_ref2) {
        var results = _ref2.results,
          helper = _ref2.helper,
          instantSearchInstance = _ref2.instantSearchInstance;
        if (!sendEvent) {
          sendEvent = createSendEventForHits({
            instantSearchInstance: instantSearchInstance,
            helper: helper,
            widgetType: this.$$type
          });
        }
        if (results === null || results === undefined) {
          return {
            items: [],
            widgetParams: widgetParams,
            sendEvent: sendEvent
          };
        }
        if (escapeHTML && results.hits.length > 0) {
          results.hits = escapeHits(results.hits);
        }
        var itemsWithAbsolutePosition = addAbsolutePosition(results.hits, 0, 1);
        var itemsWithAbsolutePositionAndQueryID = addQueryID(itemsWithAbsolutePosition, results.queryID);
        var transformedItems = transformItems(itemsWithAbsolutePositionAndQueryID, {
          results: results
        });
        return {
          items: transformedItems,
          widgetParams: widgetParams,
          sendEvent: sendEvent
        };
      },
      dispose: function dispose(_ref3) {
        var recommendState = _ref3.recommendState;
        unmountFn();
        return recommendState.removeParams(this.$$id);
      },
      getWidgetParameters: function getWidgetParameters(state) {
        return state.removeParams(this.$$id).addTrendingItems({
          facetName: facetName,
          facetValue: facetValue,
          maxRecommendations: limit,
          threshold: threshold,
          fallbackParameters: fallbackParameters ? _objectSpread(_objectSpread({}, fallbackParameters), escapeHTML ? TAG_PLACEHOLDER : {}) : undefined,
          queryParameters: _objectSpread(_objectSpread({}, queryParameters), escapeHTML ? TAG_PLACEHOLDER : {}),
          $$id: this.$$id
        });
      }
    };
  };
});