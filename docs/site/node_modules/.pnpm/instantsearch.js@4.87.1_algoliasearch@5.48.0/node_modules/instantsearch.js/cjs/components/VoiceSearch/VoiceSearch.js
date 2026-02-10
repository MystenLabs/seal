"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _preact = require("preact");
var _Template = _interopRequireDefault(require("../Template/Template"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
var VoiceSearch = function VoiceSearch(_ref) {
  var cssClasses = _ref.cssClasses,
    isBrowserSupported = _ref.isBrowserSupported,
    isListening = _ref.isListening,
    toggleListening = _ref.toggleListening,
    voiceListeningState = _ref.voiceListeningState,
    templates = _ref.templates;
  var handleClick = function handleClick(event) {
    if (event.currentTarget instanceof HTMLElement) {
      event.currentTarget.blur();
    }
    toggleListening();
  };
  var status = voiceListeningState.status,
    transcript = voiceListeningState.transcript,
    isSpeechFinal = voiceListeningState.isSpeechFinal,
    errorCode = voiceListeningState.errorCode;
  return (0, _preact.h)("div", {
    className: cssClasses.root
  }, (0, _preact.h)(_Template.default, {
    templateKey: "buttonText",
    rootTagName: "button",
    rootProps: {
      className: cssClasses.button,
      type: 'button',
      title: "Search by voice".concat(isBrowserSupported ? '' : ' (not supported on this browser)'),
      onClick: handleClick,
      disabled: !isBrowserSupported
    },
    data: {
      status: status,
      errorCode: errorCode,
      isListening: isListening,
      transcript: transcript,
      isSpeechFinal: isSpeechFinal,
      isBrowserSupported: isBrowserSupported
    },
    templates: templates
  }), (0, _preact.h)(_Template.default, {
    templateKey: "status",
    rootProps: {
      className: cssClasses.status
    },
    data: {
      status: status,
      errorCode: errorCode,
      isListening: isListening,
      transcript: transcript,
      isSpeechFinal: isSpeechFinal,
      isBrowserSupported: isBrowserSupported
    },
    templates: templates
  }));
};
var _default = exports.default = VoiceSearch;