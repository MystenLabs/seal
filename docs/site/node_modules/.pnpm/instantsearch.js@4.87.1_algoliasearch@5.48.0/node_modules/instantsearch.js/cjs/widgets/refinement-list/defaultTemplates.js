"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _formatNumber = require("../../lib/formatNumber");
var defaultTemplates = {
  item: function item(_ref) {
    var cssClasses = _ref.cssClasses,
      count = _ref.count,
      value = _ref.value,
      highlighted = _ref.highlighted,
      isRefined = _ref.isRefined,
      isFromSearch = _ref.isFromSearch;
    return (0, _preact.h)("label", {
      className: (0, _instantsearchUiComponents.cx)(cssClasses.label)
    }, (0, _preact.h)("input", {
      type: "checkbox",
      className: (0, _instantsearchUiComponents.cx)(cssClasses.checkbox),
      value: value,
      defaultChecked: isRefined
    }), (0, _preact.h)("span", {
      className: (0, _instantsearchUiComponents.cx)(cssClasses.labelText),
      dangerouslySetInnerHTML: isFromSearch ? {
        __html: highlighted
      } : undefined
    }, !isFromSearch && highlighted), (0, _preact.h)("span", {
      className: (0, _instantsearchUiComponents.cx)(cssClasses.count)
    }, (0, _formatNumber.formatNumber)(count)));
  },
  showMoreText: function showMoreText(_ref2) {
    var isShowingMore = _ref2.isShowingMore;
    return isShowingMore ? 'Show less' : 'Show more';
  },
  searchableNoResults: function searchableNoResults() {
    return 'No results';
  }
};
var _default = exports.default = defaultTemplates;