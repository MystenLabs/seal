"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _formatNumber = require("../../lib/formatNumber");
var defaultTemplates = {
  item: function item(_ref) {
    var label = _ref.label,
      count = _ref.count;
    return "".concat(label, " (").concat((0, _formatNumber.formatNumber)(count), ")");
  },
  defaultOption: function defaultOption() {
    return 'See all';
  }
};
var _default = exports.default = defaultTemplates;