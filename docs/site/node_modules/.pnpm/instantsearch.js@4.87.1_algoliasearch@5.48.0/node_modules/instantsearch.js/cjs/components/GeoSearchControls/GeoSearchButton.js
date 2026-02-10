"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _preact = require("preact");
var GeoSearchButton = function GeoSearchButton(_ref) {
  var className = _ref.className,
    _ref$disabled = _ref.disabled,
    disabled = _ref$disabled === void 0 ? false : _ref$disabled,
    onClick = _ref.onClick,
    children = _ref.children;
  return (0, _preact.h)("button", {
    className: className,
    onClick: onClick,
    disabled: disabled
  }, children);
};
var _default = exports.default = GeoSearchButton;