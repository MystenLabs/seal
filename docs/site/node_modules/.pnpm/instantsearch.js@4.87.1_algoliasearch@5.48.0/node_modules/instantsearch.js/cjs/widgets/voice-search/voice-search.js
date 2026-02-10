"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _VoiceSearch = _interopRequireDefault(require("../../components/VoiceSearch/VoiceSearch"));
var _connectVoiceSearch = _interopRequireDefault(require("../../connectors/voice-search/connectVoiceSearch"));
var _suit = require("../../lib/suit");
var _utils = require("../../lib/utils");
var _defaultTemplates = _interopRequireDefault(require("./defaultTemplates"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'voice-search'
});
var suit = (0, _suit.component)('VoiceSearch');
var renderer = function renderer(_ref) {
  var containerNode = _ref.containerNode,
    cssClasses = _ref.cssClasses,
    templates = _ref.templates;
  return function (_ref2) {
    var isBrowserSupported = _ref2.isBrowserSupported,
      isListening = _ref2.isListening,
      toggleListening = _ref2.toggleListening,
      voiceListeningState = _ref2.voiceListeningState;
    (0, _preact.render)((0, _preact.h)(_VoiceSearch.default, {
      cssClasses: cssClasses,
      templates: templates,
      isBrowserSupported: isBrowserSupported,
      isListening: isListening,
      toggleListening: toggleListening,
      voiceListeningState: voiceListeningState
    }), containerNode);
  };
};
var voiceSearch = function voiceSearch(widgetParams) {
  var _ref3 = widgetParams || {},
    container = _ref3.container,
    _ref3$cssClasses = _ref3.cssClasses,
    userCssClasses = _ref3$cssClasses === void 0 ? {} : _ref3$cssClasses,
    _ref3$templates = _ref3.templates,
    userTemplates = _ref3$templates === void 0 ? {} : _ref3$templates,
    _ref3$searchAsYouSpea = _ref3.searchAsYouSpeak,
    searchAsYouSpeak = _ref3$searchAsYouSpea === void 0 ? false : _ref3$searchAsYouSpea,
    language = _ref3.language,
    additionalQueryParameters = _ref3.additionalQueryParameters,
    createVoiceSearchHelper = _ref3.createVoiceSearchHelper;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var containerNode = (0, _utils.getContainerNode)(container);
  var cssClasses = {
    root: (0, _instantsearchUiComponents.cx)(suit(), userCssClasses.root),
    button: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'button'
    }), userCssClasses.button),
    status: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'status'
    }), userCssClasses.status)
  };
  var templates = _objectSpread(_objectSpread({}, _defaultTemplates.default), userTemplates);
  var specializedRenderer = renderer({
    containerNode: containerNode,
    cssClasses: cssClasses,
    templates: templates
  });
  var makeWidget = (0, _connectVoiceSearch.default)(specializedRenderer, function () {
    return (0, _preact.render)(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    container: containerNode,
    cssClasses: cssClasses,
    templates: templates,
    searchAsYouSpeak: searchAsYouSpeak,
    language: language,
    additionalQueryParameters: additionalQueryParameters,
    createVoiceSearchHelper: createVoiceSearchHelper
  })), {}, {
    $$widgetType: 'ais.voiceSearch'
  });
};
var _default = exports.default = voiceSearch;