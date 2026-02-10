import { cx } from 'instantsearch-ui-components';
import { h } from 'preact';
import { isSpecialClick, capitalize } from "../../lib/utils/index.js";
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
    if (isSpecialClick(event)) {
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
  return h("div", {
    className: cx(cssClasses.root, !canRefine && cssClasses.noRefinementRoot)
  }, h("ul", {
    className: cssClasses.list
  }, items.map(function (item, index) {
    return h("li", {
      key: "".concat(item.indexName, "-").concat(item.attribute, "-").concat(index),
      className: cssClasses.item
    }, h("span", {
      className: cssClasses.label
    }, capitalize(item.label), ": "), item.refinements.map(function (refinement) {
      return h("span", {
        key: createItemKey(refinement),
        className: cssClasses.category
      }, h("span", {
        className: cssClasses.categoryLabel
      }, refinement.attribute === 'query' ? h("q", null, refinement.label) : refinement.label), h("button", {
        className: cssClasses.delete,
        type: "button",
        onClick: handleClick(item.refine.bind(null, refinement))
      }, "\u2715"));
    }));
  })));
};
export default CurrentRefinements;