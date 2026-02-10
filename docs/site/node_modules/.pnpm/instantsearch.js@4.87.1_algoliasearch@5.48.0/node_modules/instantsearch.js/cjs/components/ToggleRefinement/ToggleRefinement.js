"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _preact = require("preact");
var _Template = _interopRequireDefault(require("../Template/Template"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
var ToggleRefinement = function ToggleRefinement(_ref) {
  var currentRefinement = _ref.currentRefinement,
    refine = _ref.refine,
    cssClasses = _ref.cssClasses,
    templateProps = _ref.templateProps;
  return (0, _preact.h)("div", {
    className: cssClasses.root
  }, (0, _preact.h)("label", {
    className: cssClasses.label
  }, (0, _preact.h)("input", {
    className: cssClasses.checkbox,
    type: "checkbox",
    checked: currentRefinement.isRefined,
    onChange: function onChange(event) {
      return refine({
        isRefined: !event.target.checked
      });
    }
  }), (0, _preact.h)(_Template.default, _extends({}, templateProps, {
    rootTagName: "span",
    rootProps: {
      className: cssClasses.labelText
    },
    templateKey: "labelText",
    data: currentRefinement
  }))));
};
var _default = exports.default = ToggleRefinement;