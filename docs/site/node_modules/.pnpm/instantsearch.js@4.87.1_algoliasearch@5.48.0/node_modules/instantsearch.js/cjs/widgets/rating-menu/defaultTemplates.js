"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _formatNumber = require("../../lib/formatNumber");
function ItemWrapper(_ref) {
  var children = _ref.children,
    count = _ref.count,
    value = _ref.value,
    url = _ref.url,
    cssClasses = _ref.cssClasses;
  if (count) {
    return (0, _preact.h)("a", {
      className: (0, _instantsearchUiComponents.cx)(cssClasses.link),
      "aria-label": "".concat(value, " & up"),
      href: url
    }, children);
  }
  return (0, _preact.h)("div", {
    className: (0, _instantsearchUiComponents.cx)(cssClasses.link),
    "aria-label": "".concat(value, " & up"),
    disabled: true
  }, children);
}
var defaultTemplates = {
  item: function item(_ref2) {
    var count = _ref2.count,
      value = _ref2.value,
      url = _ref2.url,
      stars = _ref2.stars,
      cssClasses = _ref2.cssClasses;
    return (0, _preact.h)(ItemWrapper, {
      count: count,
      value: value,
      url: url,
      cssClasses: cssClasses
    }, stars.map(function (isFull, index) {
      return (0, _preact.h)("svg", {
        key: index,
        className: (0, _instantsearchUiComponents.cx)(cssClasses.starIcon, isFull ? cssClasses.fullStarIcon : cssClasses.emptyStarIcon),
        "aria-hidden": "true",
        width: "24",
        height: "24"
      }, (0, _preact.h)("use", {
        xlinkHref: isFull ? '#ais-RatingMenu-starSymbol' : '#ais-RatingMenu-starEmptySymbol'
      }));
    }), (0, _preact.h)("span", {
      "aria-hidden": "true",
      className: (0, _instantsearchUiComponents.cx)(cssClasses.label)
    }, "& Up"), count && (0, _preact.h)("span", {
      className: (0, _instantsearchUiComponents.cx)(cssClasses.count)
    }, (0, _formatNumber.formatNumber)(count)));
  }
};
var _default = exports.default = defaultTemplates;