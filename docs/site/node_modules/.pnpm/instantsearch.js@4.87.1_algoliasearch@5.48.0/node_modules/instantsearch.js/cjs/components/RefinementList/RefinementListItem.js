"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _preact = require("preact");
var _Template = _interopRequireDefault(require("../Template/Template"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
function RefinementListItem(_ref) {
  var className = _ref.className,
    handleClick = _ref.handleClick,
    facetValueToRefine = _ref.facetValueToRefine,
    isRefined = _ref.isRefined,
    templateProps = _ref.templateProps,
    templateKey = _ref.templateKey,
    templateData = _ref.templateData,
    subItems = _ref.subItems;
  return (0, _preact.h)("li", {
    className: className,
    onClick: function onClick(originalEvent) {
      handleClick({
        facetValueToRefine: facetValueToRefine,
        isRefined: isRefined,
        originalEvent: originalEvent
      });
    }
  }, (0, _preact.h)(_Template.default, _extends({}, templateProps, {
    templateKey: templateKey,
    data: templateData
  })), subItems);
}
var _default = exports.default = RefinementListItem;