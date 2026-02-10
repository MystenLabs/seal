"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _utils = require("../../lib/utils");
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'hits',
  connector: true
});
var connectHits = exports.default = function connectHits(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : _utils.noop;
  (0, _utils.checkRendering)(renderFn, withUsage());
  return function (widgetParams) {
    var _ref = widgetParams || {},
      _ref$escapeHTML = _ref.escapeHTML,
      escapeHTML = _ref$escapeHTML === void 0 ? true : _ref$escapeHTML,
      _ref$transformItems = _ref.transformItems,
      transformItems = _ref$transformItems === void 0 ? function (items) {
        return items;
      } : _ref$transformItems;
    var sendEvent;
    var bindEvent;
    return {
      $$type: 'ais.hits',
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
        renderState.sendEvent('view:internal', renderState.items);
      },
      getRenderState: function getRenderState(renderState, renderOptions
      // Type is explicitly redefined, to avoid having the TWidgetParams type in the definition
      ) {
        return _objectSpread(_objectSpread({}, renderState), {}, {
          hits: this.getWidgetRenderState(renderOptions)
        });
      },
      getWidgetRenderState: function getWidgetRenderState(_ref2) {
        var _results$renderingCon, _results$renderingCon2, _results$renderingCon3;
        var results = _ref2.results,
          helper = _ref2.helper,
          instantSearchInstance = _ref2.instantSearchInstance;
        if (!sendEvent) {
          sendEvent = (0, _utils.createSendEventForHits)({
            instantSearchInstance: instantSearchInstance,
            helper: helper,
            widgetType: this.$$type
          });
        }
        if (!bindEvent) {
          bindEvent = (0, _utils.createBindEventForHits)({
            helper: helper,
            widgetType: this.$$type,
            instantSearchInstance: instantSearchInstance
          });
        }
        if (!results) {
          return {
            hits: [],
            items: [],
            results: undefined,
            banner: undefined,
            sendEvent: sendEvent,
            bindEvent: bindEvent,
            widgetParams: widgetParams
          };
        }
        if (escapeHTML && results.hits.length > 0) {
          results.hits = (0, _utils.escapeHits)(results.hits);
        }
        var hitsWithAbsolutePosition = (0, _utils.addAbsolutePosition)(results.hits, results.page, results.hitsPerPage);
        var hitsWithAbsolutePositionAndQueryID = (0, _utils.addQueryID)(hitsWithAbsolutePosition, results.queryID);
        var items = transformItems(hitsWithAbsolutePositionAndQueryID, {
          results: results
        });
        var banner = (_results$renderingCon = results.renderingContent) === null || _results$renderingCon === void 0 ? void 0 : (_results$renderingCon2 = _results$renderingCon.widgets) === null || _results$renderingCon2 === void 0 ? void 0 : (_results$renderingCon3 = _results$renderingCon2.banners) === null || _results$renderingCon3 === void 0 ? void 0 : _results$renderingCon3[0];
        return {
          hits: items,
          items: items,
          results: results,
          banner: banner,
          sendEvent: sendEvent,
          bindEvent: bindEvent,
          widgetParams: widgetParams
        };
      },
      dispose: function dispose(_ref3) {
        var state = _ref3.state;
        unmountFn();
        if (!escapeHTML) {
          return state;
        }
        return state.setQueryParameters(Object.keys(_utils.TAG_PLACEHOLDER).reduce(function (acc, key) {
          return _objectSpread(_objectSpread({}, acc), {}, _defineProperty({}, key, undefined));
        }, {}));
      },
      getWidgetSearchParameters: function getWidgetSearchParameters(state, _uiState) {
        if (!escapeHTML) {
          return state;
        }

        // @MAJOR: set this globally, not in the Hits widget to allow Hits to be conditionally used
        return state.setQueryParameters(_utils.TAG_PLACEHOLDER);
      }
    };
  };
};