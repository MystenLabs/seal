"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _utils = require("../../lib/utils");
var _voiceSearchHelper2 = _interopRequireDefault(require("../../lib/voiceSearchHelper"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'voice-search',
  connector: true
});
var connectVoiceSearch = function connectVoiceSearch(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : _utils.noop;
  (0, _utils.checkRendering)(renderFn, withUsage());
  return function (widgetParams) {
    var _widgetParams$searchA = widgetParams.searchAsYouSpeak,
      searchAsYouSpeak = _widgetParams$searchA === void 0 ? false : _widgetParams$searchA,
      language = widgetParams.language,
      additionalQueryParameters = widgetParams.additionalQueryParameters,
      _widgetParams$createV = widgetParams.createVoiceSearchHelper,
      createVoiceSearchHelper = _widgetParams$createV === void 0 ? _voiceSearchHelper2.default : _widgetParams$createV;
    return {
      $$type: 'ais.voiceSearch',
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
      getRenderState: function getRenderState(renderState, renderOptions) {
        return _objectSpread(_objectSpread({}, renderState), {}, {
          voiceSearch: this.getWidgetRenderState(renderOptions)
        });
      },
      getWidgetRenderState: function getWidgetRenderState(renderOptions) {
        var _this = this;
        var helper = renderOptions.helper,
          instantSearchInstance = renderOptions.instantSearchInstance;
        if (!this._refine) {
          this._refine = function (query) {
            if (query !== helper.state.query) {
              var queryLanguages = language ? [language.split('-')[0]] : undefined;
              // @ts-ignore queryLanguages is allowed to be a string, not just an array
              helper.setQueryParameter('queryLanguages', queryLanguages);
              if (typeof additionalQueryParameters === 'function') {
                helper.setState(helper.state.setQueryParameters(_objectSpread({
                  ignorePlurals: true,
                  removeStopWords: true,
                  // @ts-ignore optionalWords is allowed to be a string too
                  optionalWords: query
                }, additionalQueryParameters({
                  query: query
                }))));
              }
              helper.setQuery(query).search();
            }
          };
        }
        if (!this._voiceSearchHelper) {
          this._voiceSearchHelper = createVoiceSearchHelper({
            searchAsYouSpeak: searchAsYouSpeak,
            language: language,
            onQueryChange: function onQueryChange(query) {
              return _this._refine(query);
            },
            onStateChange: function onStateChange() {
              renderFn(_objectSpread(_objectSpread({}, _this.getWidgetRenderState(renderOptions)), {}, {
                instantSearchInstance: instantSearchInstance
              }), false);
            }
          });
        }
        var _voiceSearchHelper = this._voiceSearchHelper,
          isBrowserSupported = _voiceSearchHelper.isBrowserSupported,
          isListening = _voiceSearchHelper.isListening,
          startListening = _voiceSearchHelper.startListening,
          stopListening = _voiceSearchHelper.stopListening,
          getState = _voiceSearchHelper.getState;
        return {
          isBrowserSupported: isBrowserSupported(),
          isListening: isListening(),
          toggleListening: function toggleListening() {
            if (!isBrowserSupported()) {
              return;
            }
            if (isListening()) {
              stopListening();
            } else {
              startListening();
            }
          },
          voiceListeningState: getState(),
          widgetParams: widgetParams
        };
      },
      dispose: function dispose(_ref) {
        var state = _ref.state;
        this._voiceSearchHelper.dispose();
        unmountFn();
        var newState = state;
        if (typeof additionalQueryParameters === 'function') {
          var additional = additionalQueryParameters({
            query: ''
          });
          var toReset = additional ? Object.keys(additional).reduce(function (acc, current) {
            // @ts-ignore search parameters is typed as readonly in v4
            acc[current] = undefined;
            return acc;
          }, {}) : {};
          newState = state.setQueryParameters(_objectSpread({
            // @ts-ignore (queryLanguages is not added to algoliasearch v3)
            queryLanguages: undefined,
            ignorePlurals: undefined,
            removeStopWords: undefined,
            optionalWords: undefined
          }, toReset));
        }
        return newState.setQueryParameter('query', undefined);
      },
      getWidgetUiState: function getWidgetUiState(uiState, _ref2) {
        var searchParameters = _ref2.searchParameters;
        var query = searchParameters.query || '';
        if (!query) {
          return uiState;
        }
        return _objectSpread(_objectSpread({}, uiState), {}, {
          query: query
        });
      },
      getWidgetSearchParameters: function getWidgetSearchParameters(searchParameters, _ref3) {
        var uiState = _ref3.uiState;
        return searchParameters.setQueryParameter('query', uiState.query || '');
      }
    };
  };
};
var _default = exports.default = connectVoiceSearch;