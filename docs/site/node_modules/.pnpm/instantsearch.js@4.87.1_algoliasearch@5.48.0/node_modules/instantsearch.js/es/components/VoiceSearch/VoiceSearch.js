import { h } from 'preact';
import Template from "../Template/Template.js";
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
  return h("div", {
    className: cssClasses.root
  }, h(Template, {
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
  }), h(Template, {
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
export default VoiceSearch;