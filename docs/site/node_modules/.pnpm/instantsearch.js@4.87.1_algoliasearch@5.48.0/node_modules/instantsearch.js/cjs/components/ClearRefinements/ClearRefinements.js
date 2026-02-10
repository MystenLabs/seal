"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _Template = _interopRequireDefault(require("../Template/Template"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
var ClearRefinements = function ClearRefinements(_ref) {
  var hasRefinements = _ref.hasRefinements,
    refine = _ref.refine,
    cssClasses = _ref.cssClasses,
    templateProps = _ref.templateProps;
  return (0, _preact.h)("div", {
    className: cssClasses.root
  }, (0, _preact.h)(_Template.default, _extends({}, templateProps, {
    templateKey: "resetLabel",
    rootTagName: "button",
    rootProps: {
      className: (0, _instantsearchUiComponents.cx)(cssClasses.button, !hasRefinements && cssClasses.disabledButton),
      onClick: refine,
      disabled: !hasRefinements
    },
    data: {
      hasRefinements: hasRefinements
    }
  })));
};
var _default = exports.default = ClearRefinements;