"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
// `SpeechRecognition` is an API used on the browser so we can safely disable
// the `window` check.
/* eslint-disable no-restricted-globals */
/* global SpeechRecognition SpeechRecognitionEvent */

var createVoiceSearchHelper = function createVoiceSearchHelper(_ref) {
  var searchAsYouSpeak = _ref.searchAsYouSpeak,
    language = _ref.language,
    onQueryChange = _ref.onQueryChange,
    onStateChange = _ref.onStateChange;
  var SpeechRecognitionAPI = window.webkitSpeechRecognition || window.SpeechRecognition;
  var getDefaultState = function getDefaultState(status) {
    return {
      status: status,
      transcript: '',
      isSpeechFinal: false,
      errorCode: undefined
    };
  };
  var state = getDefaultState('initial');
  var recognition;
  var isBrowserSupported = function isBrowserSupported() {
    return Boolean(SpeechRecognitionAPI);
  };
  var isListening = function isListening() {
    return state.status === 'askingPermission' || state.status === 'waiting' || state.status === 'recognizing';
  };
  var setState = function setState() {
    var newState = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
    state = _objectSpread(_objectSpread({}, state), newState);
    onStateChange();
  };
  var getState = function getState() {
    return state;
  };
  var resetState = function resetState() {
    var status = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 'initial';
    setState(getDefaultState(status));
  };
  var onStart = function onStart() {
    setState({
      status: 'waiting'
    });
  };
  var onError = function onError(event) {
    setState({
      status: 'error',
      errorCode: event.error
    });
  };
  var onResult = function onResult(event) {
    setState({
      status: 'recognizing',
      transcript: event.results[0] && event.results[0][0] && event.results[0][0].transcript || '',
      isSpeechFinal: event.results[0] && event.results[0].isFinal
    });
    if (searchAsYouSpeak && state.transcript) {
      onQueryChange(state.transcript);
    }
  };
  var onEnd = function onEnd() {
    if (!state.errorCode && state.transcript && !searchAsYouSpeak) {
      onQueryChange(state.transcript);
    }
    if (state.status !== 'error') {
      setState({
        status: 'finished'
      });
    }
  };
  var startListening = function startListening() {
    recognition = new SpeechRecognitionAPI();
    if (!recognition) {
      return;
    }
    resetState('askingPermission');
    recognition.interimResults = true;
    if (language) {
      recognition.lang = language;
    }
    recognition.addEventListener('start', onStart);
    recognition.addEventListener('error', onError);
    recognition.addEventListener('result', onResult);
    recognition.addEventListener('end', onEnd);
    recognition.start();
  };
  var dispose = function dispose() {
    if (!recognition) {
      return;
    }
    recognition.stop();
    recognition.removeEventListener('start', onStart);
    recognition.removeEventListener('error', onError);
    recognition.removeEventListener('result', onResult);
    recognition.removeEventListener('end', onEnd);
    recognition = undefined;
  };
  var stopListening = function stopListening() {
    dispose();
    // Because `dispose` removes event listeners, `end` listener is not called.
    // So we're setting the `status` as `finished` here.
    // If we don't do it, it will be still `waiting` or `recognizing`.
    resetState('finished');
  };
  return {
    getState: getState,
    isBrowserSupported: isBrowserSupported,
    isListening: isListening,
    startListening: startListening,
    stopListening: stopListening,
    dispose: dispose
  };
};
var _default = exports.default = createVoiceSearchHelper;