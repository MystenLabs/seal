import { Fragment, h } from 'preact';
var _ref2 = h(Fragment, null, h("line", {
  x1: "1",
  y1: "1",
  x2: "23",
  y2: "23"
}), h("path", {
  d: "M9 9v3a3 3 0 0 0 5.12 2.12M15 9.34V4a3 3 0 0 0-5.94-.6"
}), h("path", {
  d: "M17 16.95A7 7 0 0 1 5 12v-2m14 0v2a7 7 0 0 1-.11 1.23"
}), h("line", {
  x1: "12",
  y1: "19",
  x2: "12",
  y2: "23"
}), h("line", {
  x1: "8",
  y1: "23",
  x2: "16",
  y2: "23"
}));
var _ref3 = h("path", {
  d: "M19 10v2a7 7 0 0 1-14 0v-2"
});
var _ref4 = h("line", {
  x1: "12",
  y1: "19",
  x2: "12",
  y2: "23"
});
var _ref5 = h("line", {
  x1: "8",
  y1: "23",
  x2: "16",
  y2: "23"
});
var ButtonInnerElement = function ButtonInnerElement(_ref) {
  var status = _ref.status,
    errorCode = _ref.errorCode,
    isListening = _ref.isListening;
  if (status === 'error' && errorCode === 'not-allowed') {
    return _ref2;
  }
  return h(Fragment, null, h("path", {
    d: "M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z",
    fill: isListening ? 'currentColor' : 'none'
  }), _ref3, _ref4, _ref5);
};
var defaultTemplates = {
  buttonText: function buttonText(_ref6) {
    var status = _ref6.status,
      errorCode = _ref6.errorCode,
      isListening = _ref6.isListening;
    return h("svg", {
      width: "16",
      height: "16",
      viewBox: "0 0 24 24",
      fill: "none",
      stroke: "currentColor"
      /* eslint-disable react/no-unknown-property */
      // Preact supports kebab case attributes, and using camel case would
      // require using `preact/compat`.
      // @TODO: reconsider using the `react` ESLint preset
      ,
      "stroke-width": "2",
      "stroke-linecap": "round",
      "stroke-linejoin": "round"
      /* eslint-enable react/no-unknown-property */
    }, h(ButtonInnerElement, {
      status: status,
      errorCode: errorCode,
      isListening: isListening
    }));
  },
  status: function status(_ref7) {
    var transcript = _ref7.transcript;
    return h("p", null, transcript);
  }
};
export default defaultTemplates;