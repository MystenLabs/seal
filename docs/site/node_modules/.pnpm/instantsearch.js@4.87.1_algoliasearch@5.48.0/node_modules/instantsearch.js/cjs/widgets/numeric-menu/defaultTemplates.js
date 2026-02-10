"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _preact = require("preact");
var defaultTemplates = {
  item: function item(_ref) {
    var cssClasses = _ref.cssClasses,
      attribute = _ref.attribute,
      label = _ref.label,
      isRefined = _ref.isRefined;
    return (0, _preact.h)("label", {
      className: cssClasses.label
    }, (0, _preact.h)("input", {
      type: "radio",
      className: cssClasses.radio,
      name: attribute,
      defaultChecked: isRefined
    }), (0, _preact.h)("span", {
      className: cssClasses.labelText
    }, label));
  }
};
var _default = exports.default = defaultTemplates;