"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.createRouterMiddleware = void 0;
var _history = _interopRequireDefault(require("../lib/routers/history"));
var _simple = _interopRequireDefault(require("../lib/stateMappings/simple"));
var _utils = require("../lib/utils");
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
var createRouterMiddleware = exports.createRouterMiddleware = function createRouterMiddleware() {
  var props = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
  var _props$router = props.router,
    router = _props$router === void 0 ? (0, _history.default)() : _props$router,
    _props$stateMapping = props.stateMapping,
    stateMapping = _props$stateMapping === void 0 ? (0, _simple.default)() : _props$stateMapping,
    _props$$$internal = props.$$internal,
    $$internal = _props$$$internal === void 0 ? false : _props$$$internal;
  return function (_ref) {
    var instantSearchInstance = _ref.instantSearchInstance;
    function topLevelCreateURL(nextState) {
      var previousUiState =
      // If only the mainIndex is initialized, we don't yet know what other
      // index widgets are used. Therefore we fall back to the initialUiState.
      // We can't indiscriminately use the initialUiState because then we
      // reintroduce state that was changed by the user.
      // When there are no widgets, we are sure the user can't yet have made
      // any changes.
      instantSearchInstance.mainIndex.getWidgets().length === 0 ? instantSearchInstance._initialUiState : instantSearchInstance.mainIndex.getWidgetUiState({});
      var uiState = Object.keys(nextState).reduce(function (acc, indexId) {
        return _objectSpread(_objectSpread({}, acc), {}, _defineProperty({}, indexId, nextState[indexId]));
      }, previousUiState);
      var route = stateMapping.stateToRoute(uiState);
      return router.createURL(route);
    }

    // casting to UiState here to keep createURL unaware of custom UiState
    // (as long as it's an object, it's ok)
    instantSearchInstance._createURL = topLevelCreateURL;
    var lastRouteState = undefined;
    var initialUiState = instantSearchInstance._initialUiState;
    return {
      $$type: "ais.router({router:".concat(router.$$type || '__unknown__', ", stateMapping:").concat(stateMapping.$$type || '__unknown__', "})"),
      $$internal: $$internal,
      onStateChange: function onStateChange(_ref2) {
        var uiState = _ref2.uiState;
        var routeState = stateMapping.stateToRoute(uiState);
        if (lastRouteState === undefined || !(0, _utils.isEqual)(lastRouteState, routeState)) {
          router.write(routeState);
          lastRouteState = routeState;
        }
      },
      subscribe: function subscribe() {
        process.env.NODE_ENV === 'development' ? (0, _utils.warning)(Object.keys(initialUiState).length === 0, 'Using `initialUiState` together with routing is not recommended. The `initialUiState` will be overwritten by the URL parameters.') : void 0;
        instantSearchInstance._initialUiState = _objectSpread(_objectSpread({}, initialUiState), stateMapping.routeToState(router.read()));
        router.onUpdate(function (route) {
          if (instantSearchInstance.mainIndex.getWidgets().length > 0) {
            instantSearchInstance.setUiState(stateMapping.routeToState(route));
          }
        });
      },
      started: function started() {
        var _router$start;
        (_router$start = router.start) === null || _router$start === void 0 ? void 0 : _router$start.call(router);
      },
      unsubscribe: function unsubscribe() {
        router.dispose();
      }
    };
  };
};