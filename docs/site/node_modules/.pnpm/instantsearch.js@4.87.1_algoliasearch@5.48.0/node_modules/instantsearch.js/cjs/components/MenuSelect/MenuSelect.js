"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _utils = require("../../lib/utils");
var _Template = _interopRequireDefault(require("../Template/Template"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
function MenuSelect(_ref) {
  var cssClasses = _ref.cssClasses,
    templateProps = _ref.templateProps,
    items = _ref.items,
    refine = _ref.refine;
  var _ref2 = (0, _utils.find)(items, function (item) {
      return item.isRefined;
    }) || {
      value: ''
    },
    selectedValue = _ref2.value;
  return (0, _preact.h)("div", {
    className: (0, _instantsearchUiComponents.cx)(cssClasses.root, items.length === 0 && cssClasses.noRefinementRoot)
  }, (0, _preact.h)("select", {
    className: cssClasses.select,
    value: selectedValue,
    onChange: function onChange(event) {
      refine(event.target.value);
    }
  }, (0, _preact.h)(_Template.default, _extends({}, templateProps, {
    templateKey: "defaultOption",
    rootTagName: "option",
    rootProps: {
      value: '',
      className: cssClasses.option
    }
  })), items.map(function (item) {
    return (0, _preact.h)(_Template.default, _extends({}, templateProps, {
      templateKey: "item",
      rootTagName: "option",
      rootProps: {
        value: item.value,
        className: cssClasses.option
      },
      key: item.value,
      data: item
    }));
  })));
}
var _default = exports.default = MenuSelect;