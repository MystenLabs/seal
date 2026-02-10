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
  name: 'analytics'
});
// @major this widget will be removed from the next major version.
var analytics = function analytics(widgetParams) {
  var _ref = widgetParams || {},
    pushFunction = _ref.pushFunction,
    _ref$delay = _ref.delay,
    delay = _ref$delay === void 0 ? 3000 : _ref$delay,
    _ref$triggerOnUIInter = _ref.triggerOnUIInteraction,
    triggerOnUIInteraction = _ref$triggerOnUIInter === void 0 ? false : _ref$triggerOnUIInter,
    _ref$pushInitialSearc = _ref.pushInitialSearch,
    pushInitialSearch = _ref$pushInitialSearc === void 0 ? true : _ref$pushInitialSearc,
    _ref$pushPagination = _ref.pushPagination,
    pushPagination = _ref$pushPagination === void 0 ? false : _ref$pushPagination;
  if (!pushFunction) {
    throw new Error(withUsage('The `pushFunction` option is required.'));
  }
  process.env.NODE_ENV === 'development' ? (0, _utils.warning)(false, "`analytics` widget has been deprecated. It is still supported in 4.x releases, but not further. It is replaced by the `insights` middleware.\n\nFor the migration, visit https://www.algolia.com/doc/guides/building-search-ui/upgrade-guides/js/#analytics-widget") : void 0;
  var cachedState = null;
  var serializeRefinements = function serializeRefinements(parameters) {
    var refinements = [];

    // eslint-disable-next-line no-restricted-syntax
    for (var parameter in parameters) {
      if (parameters.hasOwnProperty(parameter)) {
        var values = parameters[parameter].join('+');
        refinements.push("".concat(encodeURIComponent(parameter), "=").concat(encodeURIComponent(parameter), "_").concat(encodeURIComponent(values)));
      }
    }
    return refinements.join('&');
  };
  var serializeNumericRefinements = function serializeNumericRefinements(numericRefinements) {
    var refinements = [];

    // eslint-disable-next-line no-restricted-syntax
    for (var attribute in numericRefinements) {
      if (numericRefinements.hasOwnProperty(attribute)) {
        var filter = numericRefinements[attribute];
        if (filter.hasOwnProperty('>=') && filter.hasOwnProperty('<=')) {
          if (filter['>='] && filter['>='][0] === filter['<='] && filter['<='][0]) {
            refinements.push("".concat(attribute, "=").concat(attribute, "_").concat(filter['>=']));
          } else {
            refinements.push("".concat(attribute, "=").concat(attribute, "_").concat(filter['>='], "to").concat(filter['<=']));
          }
        } else if (filter.hasOwnProperty('>=')) {
          refinements.push("".concat(attribute, "=").concat(attribute, "_from").concat(filter['>=']));
        } else if (filter.hasOwnProperty('<=')) {
          refinements.push("".concat(attribute, "=").concat(attribute, "_to").concat(filter['<=']));
        } else if (filter.hasOwnProperty('=')) {
          var equals = [];

          // eslint-disable-next-line no-restricted-syntax
          for (var equal in filter['=']) {
            // eslint-disable-next-line max-depth
            if (filter['='].hasOwnProperty(equal)) {
              // @ts-ignore somehow 'equal' is a string, even though it's a number?
              equals.push(filter['='][equal]);
            }
          }
          refinements.push("".concat(attribute, "=").concat(attribute, "_").concat(equals.join('-')));
        }
      }
    }
    return refinements.join('&');
  };
  var lastSentData = '';
  var sendAnalytics = function sendAnalytics(analyticsState) {
    if (analyticsState === null) {
      return;
    }
    var serializedParams = [];
    var serializedRefinements = serializeRefinements(_objectSpread(_objectSpread(_objectSpread({}, analyticsState.state.disjunctiveFacetsRefinements), analyticsState.state.facetsRefinements), analyticsState.state.hierarchicalFacetsRefinements));
    var serializedNumericRefinements = serializeNumericRefinements(analyticsState.state.numericRefinements);
    if (serializedRefinements !== '') {
      serializedParams.push(serializedRefinements);
    }
    if (serializedNumericRefinements !== '') {
      serializedParams.push(serializedNumericRefinements);
    }
    var stringifiedParams = serializedParams.join('&');
    var dataToSend = "Query: ".concat(analyticsState.state.query || '', ", ").concat(stringifiedParams);
    if (pushPagination === true) {
      dataToSend += ", Page: ".concat(analyticsState.state.page || 0);
    }
    if (lastSentData !== dataToSend) {
      pushFunction(stringifiedParams, analyticsState.state, analyticsState.results);
      lastSentData = dataToSend;
    }
  };
  var pushTimeout;
  var isInitialSearch = true;
  if (pushInitialSearch === true) {
    isInitialSearch = false;
  }
  var onClick = function onClick() {
    sendAnalytics(cachedState);
  };
  var onUnload = function onUnload() {
    sendAnalytics(cachedState);
  };
  return {
    $$type: 'ais.analytics',
    $$widgetType: 'ais.analytics',
    init: function init() {
      if (triggerOnUIInteraction === true) {
        document.addEventListener('click', onClick);
        window.addEventListener('beforeunload', onUnload);
      }
    },
    render: function render(_ref2) {
      var results = _ref2.results,
        state = _ref2.state;
      if (!results) {
        return;
      }
      if (isInitialSearch === true) {
        isInitialSearch = false;
        return;
      }
      cachedState = {
        results: results,
        state: state
      };
      if (pushTimeout) {
        clearTimeout(pushTimeout);
      }
      pushTimeout = window.setTimeout(function () {
        return sendAnalytics(cachedState);
      }, delay);
    },
    dispose: function dispose() {
      if (triggerOnUIInteraction === true) {
        document.removeEventListener('click', onClick);
        window.removeEventListener('beforeunload', onUnload);
      }
    },
    getRenderState: function getRenderState(renderState, renderOptions) {
      return _objectSpread(_objectSpread({}, renderState), {}, {
        analytics: this.getWidgetRenderState(renderOptions)
      });
    },
    getWidgetRenderState: function getWidgetRenderState() {
      return {
        widgetParams: widgetParams
      };
    }
  };
};
var _default = exports.default = analytics;