import { cx } from 'instantsearch-ui-components';
import { h } from 'preact';
import { formatNumber } from "../../lib/formatNumber.js";
var defaultTemplates = {
  item: function item(_ref) {
    var url = _ref.url,
      label = _ref.label,
      count = _ref.count,
      cssClasses = _ref.cssClasses,
      isRefined = _ref.isRefined;
    return h("a", {
      className: cx(cx(cssClasses.link), cx(isRefined ? cssClasses.selectedItemLink : undefined)),
      href: url
    }, h("span", {
      className: cx(cssClasses.label)
    }, label), h("span", {
      className: cx(cssClasses.count)
    }, formatNumber(count)));
  },
  showMoreText: function showMoreText(_ref2) {
    var isShowingMore = _ref2.isShowingMore;
    return isShowingMore ? 'Show less' : 'Show more';
  }
};
export default defaultTemplates;