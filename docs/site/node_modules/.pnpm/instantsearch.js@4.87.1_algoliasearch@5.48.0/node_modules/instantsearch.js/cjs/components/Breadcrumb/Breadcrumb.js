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
var Breadcrumb = function Breadcrumb(_ref) {
  var items = _ref.items,
    cssClasses = _ref.cssClasses,
    templateProps = _ref.templateProps,
    createURL = _ref.createURL,
    refine = _ref.refine;
  return (0, _preact.h)("div", {
    className: (0, _instantsearchUiComponents.cx)(cssClasses.root, items.length === 0 && cssClasses.noRefinementRoot)
  }, (0, _preact.h)("ul", {
    className: cssClasses.list
  }, (0, _preact.h)("li", {
    className: (0, _instantsearchUiComponents.cx)(cssClasses.item, items.length === 0 && cssClasses.selectedItem)
  }, (0, _preact.h)(_Template.default, _extends({}, templateProps, {
    templateKey: "home",
    rootTagName: "a",
    rootProps: {
      className: cssClasses.link,
      href: createURL(null),
      onClick: function onClick(event) {
        if ((0, _utils.isSpecialClick)(event)) {
          return;
        }
        event.preventDefault();
        refine(null);
      }
    }
  }))), items.map(function (item, idx) {
    var isLast = idx === items.length - 1;
    return (0, _preact.h)("li", {
      key: item.label + idx,
      className: (0, _instantsearchUiComponents.cx)(cssClasses.item, isLast && cssClasses.selectedItem)
    }, (0, _preact.h)(_Template.default, _extends({}, templateProps, {
      templateKey: "separator",
      rootTagName: "span",
      rootProps: {
        className: cssClasses.separator,
        'aria-hidden': true
      }
    })), isLast ? item.label : (0, _preact.h)("a", {
      className: cssClasses.link,
      href: createURL(item.value),
      onClick: function onClick(event) {
        if ((0, _utils.isSpecialClick)(event)) {
          return;
        }
        event.preventDefault();
        refine(item.value);
      }
    }, item.label));
  })));
};
var _default = exports.default = Breadcrumb;