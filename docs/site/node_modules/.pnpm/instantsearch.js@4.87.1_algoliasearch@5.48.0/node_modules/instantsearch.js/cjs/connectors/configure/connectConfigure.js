"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _algoliasearchHelper = _interopRequireDefault(require("algoliasearch-helper"));
var _utils = require("../../lib/utils");
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
/**
 * Refine the given search parameters.
 */

var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'configure',
  connector: true
});
function getInitialSearchParameters(state, widgetParams) {
  // We leverage the helper internals to remove the `widgetParams` from
  // the state. The function `setQueryParameters` omits the values that
  // are `undefined` on the next state.
  return state.setQueryParameters(Object.keys(widgetParams.searchParameters).reduce(function (acc, key) {
    return _objectSpread(_objectSpread({}, acc), {}, _defineProperty({}, key, undefined));
  }, {}));
}
var connectConfigure = function connectConfigure() {
  var renderFn = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : _utils.noop;
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : _utils.noop;
  return function (widgetParams) {
    if (!widgetParams || !(0, _utils.isPlainObject)(widgetParams.searchParameters)) {
      throw new Error(withUsage('The `searchParameters` option expects an object.'));
    }
    var connectorState = {};
    function refine(helper) {
      return function (searchParameters) {
        // Merge new `searchParameters` with the ones set from other widgets
        var actualState = getInitialSearchParameters(helper.state, widgetParams);
        var nextSearchParameters = (0, _utils.mergeSearchParameters)(actualState, new _algoliasearchHelper.default.SearchParameters(searchParameters));

        // Update original `widgetParams.searchParameters` to the new refined one
        widgetParams.searchParameters = searchParameters;

        // Trigger a search with the resolved search parameters
        helper.setState(nextSearchParameters).search();
      };
    }
    return {
      $$type: 'ais.configure',
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
      dispose: function dispose(_ref) {
        var state = _ref.state;
        unmountFn();
        return getInitialSearchParameters(state, widgetParams);
      },
      getRenderState: function getRenderState(renderState, renderOptions) {
        var _renderState$configur;
        var widgetRenderState = this.getWidgetRenderState(renderOptions);
        return _objectSpread(_objectSpread({}, renderState), {}, {
          configure: _objectSpread(_objectSpread({}, widgetRenderState), {}, {
            widgetParams: _objectSpread(_objectSpread({}, widgetRenderState.widgetParams), {}, {
              searchParameters: (0, _utils.mergeSearchParameters)(new _algoliasearchHelper.default.SearchParameters((_renderState$configur = renderState.configure) === null || _renderState$configur === void 0 ? void 0 : _renderState$configur.widgetParams.searchParameters), new _algoliasearchHelper.default.SearchParameters(widgetRenderState.widgetParams.searchParameters)).getQueryParams()
            })
          })
        });
      },
      getWidgetRenderState: function getWidgetRenderState(_ref2) {
        var helper = _ref2.helper;
        if (!connectorState.refine) {
          connectorState.refine = refine(helper);
        }
        return {
          refine: connectorState.refine,
          widgetParams: widgetParams
        };
      },
      getWidgetSearchParameters: function getWidgetSearchParameters(state, _ref3) {
        var uiState = _ref3.uiState;
        return (0, _utils.mergeSearchParameters)(state, new _algoliasearchHelper.default.SearchParameters(_objectSpread(_objectSpread({}, uiState.configure), widgetParams.searchParameters)));
      },
      getWidgetUiState: function getWidgetUiState(uiState) {
        return _objectSpread(_objectSpread({}, uiState), {}, {
          configure: _objectSpread(_objectSpread({}, uiState.configure), widgetParams.searchParameters)
        });
      }
    };
  };
};
var _default = exports.default = connectConfigure;