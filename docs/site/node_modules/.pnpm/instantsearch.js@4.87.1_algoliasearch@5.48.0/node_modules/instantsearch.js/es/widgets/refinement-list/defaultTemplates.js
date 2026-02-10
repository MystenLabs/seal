import { cx } from 'instantsearch-ui-components';
import { h } from 'preact';
import { formatNumber } from "../../lib/formatNumber.js";
var defaultTemplates = {
  item: function item(_ref) {
    var cssClasses = _ref.cssClasses,
      count = _ref.count,
      value = _ref.value,
      highlighted = _ref.highlighted,
      isRefined = _ref.isRefined,
      isFromSearch = _ref.isFromSearch;
    return h("label", {
      className: cx(cssClasses.label)
    }, h("input", {
      type: "checkbox",
      className: cx(cssClasses.checkbox),
      value: value,
      defaultChecked: isRefined
    }), h("span", {
      className: cx(cssClasses.labelText),
      dangerouslySetInnerHTML: isFromSearch ? {
        __html: highlighted
      } : undefined
    }, !isFromSearch && highlighted), h("span", {
      className: cx(cssClasses.count)
    }, formatNumber(count)));
  },
  showMoreText: function showMoreText(_ref2) {
    var isShowingMore = _ref2.isShowingMore;
    return isShowingMore ? 'Show less' : 'Show more';
  },
  searchableNoResults: function searchableNoResults() {
    return 'No results';
  }
};
export default defaultTemplates;