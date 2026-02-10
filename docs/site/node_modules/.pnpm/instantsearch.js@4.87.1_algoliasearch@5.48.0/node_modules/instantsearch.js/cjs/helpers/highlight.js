"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = highlight;
var _suit = require("../lib/suit");
var _utils = require("../lib/utils");
var suit = (0, _suit.component)('Highlight');

/**
 * @deprecated use html tagged templates and the Highlight component instead
 */
function highlight(_ref) {
  var attribute = _ref.attribute,
    _ref$highlightedTagNa = _ref.highlightedTagName,
    highlightedTagName = _ref$highlightedTagNa === void 0 ? 'mark' : _ref$highlightedTagNa,
    hit = _ref.hit,
    _ref$cssClasses = _ref.cssClasses,
    cssClasses = _ref$cssClasses === void 0 ? {} : _ref$cssClasses;
  process.env.NODE_ENV === 'development' ? (0, _utils.warning)(false, "`instantsearch.highlight` function has been deprecated. It is still supported in 4.x releases, but not further. It is replaced by the `Highlight` component.\n\nFor more information, visit https://www.algolia.com/doc/guides/building-search-ui/upgrade-guides/js/?client=html+tagged+templates#upgrade-templates") : void 0;
  var highlightAttributeResult = (0, _utils.getPropertyByPath)(hit._highlightResult, attribute);

  // @MAJOR fallback to attribute value if highlight is not found
  process.env.NODE_ENV === 'development' ? (0, _utils.warning)(highlightAttributeResult, "Could not enable highlight for \"".concat(attribute, "\", will display an empty string.\nPlease check whether this attribute exists and is either searchable or specified in `attributesToHighlight`.\n\nSee: https://alg.li/highlighting\n")) : void 0;
  var _ref2 = highlightAttributeResult || {},
    _ref2$value = _ref2.value,
    attributeValue = _ref2$value === void 0 ? '' : _ref2$value;

  // cx is not used, since it would be bundled as a dependency for Vue
  var className = suit({
    descendantName: 'highlighted'
  }) + (cssClasses.highlighted ? " ".concat(cssClasses.highlighted) : '');
  return attributeValue.replace(new RegExp(_utils.TAG_REPLACEMENT.highlightPreTag, 'g'), "<".concat(highlightedTagName, " class=\"").concat(className, "\">")).replace(new RegExp(_utils.TAG_REPLACEMENT.highlightPostTag, 'g'), "</".concat(highlightedTagName, ">"));
}