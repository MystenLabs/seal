"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _preact = require("preact");
var _Template = _interopRequireDefault(require("../Template/Template"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
var QueryRuleCustomData = function QueryRuleCustomData(_ref) {
  var cssClasses = _ref.cssClasses,
    templates = _ref.templates,
    items = _ref.items;
  return (0, _preact.h)(_Template.default, {
    templateKey: "default",
    templates: templates,
    rootProps: {
      className: cssClasses.root
    },
    data: {
      items: items
    }
  });
};
var _default = exports.default = QueryRuleCustomData;