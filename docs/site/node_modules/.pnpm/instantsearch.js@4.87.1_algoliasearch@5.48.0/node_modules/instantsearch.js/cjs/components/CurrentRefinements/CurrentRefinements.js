"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _utils = require("../../lib/utils");
var createItemKey = function createItemKey(_ref) {
  var attribute = _ref.attribute,
    value = _ref.value,
    type = _ref.type,
    operator = _ref.operator;
  return [attribute, type, value, operator].map(function (key) {
    return key;
  }).filter(Boolean).join(':');
};
var handleClick = function handleClick(callback) {
  return function (event) {
    if ((0, _utils.isSpecialClick)(event)) {
      return;
    }
    event.preventDefault();
    callback();
  };
};
var CurrentRefinements = function CurrentRefinements(_ref2) {
  var items = _ref2.items,
    cssClasses = _ref2.cssClasses,
    canRefine = _ref2.canRefine;
  return (0, _preact.h)("div", {
    className: (0, _instantsearchUiComponents.cx)(cssClasses.root, !canRefine && cssClasses.noRefinementRoot)
  }, (0, _preact.h)("ul", {
    className: cssClasses.list
  }, items.map(function (item, index) {
    return (0, _preact.h)("li", {
      key: "".concat(item.indexName, "-").concat(item.attribute, "-").concat(index),
      className: cssClasses.item
    }, (0, _preact.h)("span", {
      className: cssClasses.label
    }, (0, _utils.capitalize)(item.label), ": "), item.refinements.map(function (refinement) {
      return (0, _preact.h)("span", {
        key: createItemKey(refinement),
        className: cssClasses.category
      }, (0, _preact.h)("span", {
        className: cssClasses.categoryLabel
      }, refinement.attribute === 'query' ? (0, _preact.h)("q", null, refinement.label) : refinement.label), (0, _preact.h)("button", {
        className: cssClasses.delete,
        type: "button",
        onClick: handleClick(item.refine.bind(null, refinement))
      }, "\u2715"));
    }));
  })));
};
var _default = exports.default = CurrentRefinements;