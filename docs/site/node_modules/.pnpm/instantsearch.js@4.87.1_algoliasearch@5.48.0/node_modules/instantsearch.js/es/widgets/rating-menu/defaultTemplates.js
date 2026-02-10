import { cx } from 'instantsearch-ui-components';
import { h } from 'preact';
import { formatNumber } from "../../lib/formatNumber.js";
function ItemWrapper(_ref) {
  var children = _ref.children,
    count = _ref.count,
    value = _ref.value,
    url = _ref.url,
    cssClasses = _ref.cssClasses;
  if (count) {
    return h("a", {
      className: cx(cssClasses.link),
      "aria-label": "".concat(value, " & up"),
      href: url
    }, children);
  }
  return h("div", {
    className: cx(cssClasses.link),
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
    return h(ItemWrapper, {
      count: count,
      value: value,
      url: url,
      cssClasses: cssClasses
    }, stars.map(function (isFull, index) {
      return h("svg", {
        key: index,
        className: cx(cssClasses.starIcon, isFull ? cssClasses.fullStarIcon : cssClasses.emptyStarIcon),
        "aria-hidden": "true",
        width: "24",
        height: "24"
      }, h("use", {
        xlinkHref: isFull ? '#ais-RatingMenu-starSymbol' : '#ais-RatingMenu-starEmptySymbol'
      }));
    }), h("span", {
      "aria-hidden": "true",
      className: cx(cssClasses.label)
    }, "& Up"), count && h("span", {
      className: cx(cssClasses.count)
    }, formatNumber(count)));
  }
};
export default defaultTemplates;