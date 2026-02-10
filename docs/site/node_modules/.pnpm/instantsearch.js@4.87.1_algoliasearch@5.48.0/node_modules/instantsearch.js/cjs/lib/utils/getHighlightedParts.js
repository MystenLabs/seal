"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getHighlightedParts = getHighlightedParts;
var _escapeHighlight = require("./escape-highlight");
function getHighlightedParts(highlightedValue) {
  // @MAJOR: this should use TAG_PLACEHOLDER
  var highlightPostTag = _escapeHighlight.TAG_REPLACEMENT.highlightPostTag,
    highlightPreTag = _escapeHighlight.TAG_REPLACEMENT.highlightPreTag;
  var splitByPreTag = highlightedValue.split(highlightPreTag);
  var firstValue = splitByPreTag.shift();
  var elements = !firstValue ? [] : [{
    value: firstValue,
    isHighlighted: false
  }];
  splitByPreTag.forEach(function (split) {
    var splitByPostTag = split.split(highlightPostTag);
    elements.push({
      value: splitByPostTag[0],
      isHighlighted: true
    });
    if (splitByPostTag[1] !== '') {
      elements.push({
        value: splitByPostTag[1],
        isHighlighted: false
      });
    }
  });
  return elements;
}