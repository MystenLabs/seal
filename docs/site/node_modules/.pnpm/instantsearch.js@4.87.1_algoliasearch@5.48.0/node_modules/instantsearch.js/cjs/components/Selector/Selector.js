"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
function Selector(_ref) {
  var currentValue = _ref.currentValue,
    options = _ref.options,
    cssClasses = _ref.cssClasses,
    setValue = _ref.setValue,
    ariaLabel = _ref.ariaLabel;
  return (0, _preact.h)("select", {
    className: (0, _instantsearchUiComponents.cx)(cssClasses.select),
    onChange: function onChange(event) {
      return setValue(event.target.value);
    },
    value: "".concat(currentValue),
    "aria-label": ariaLabel
  }, options.map(function (option) {
    return (0, _preact.h)("option", {
      className: (0, _instantsearchUiComponents.cx)(cssClasses.option),
      key: option.label + option.value,
      value: "".concat(option.value)
    }, option.label);
  }));
}
var _default = exports.default = Selector;