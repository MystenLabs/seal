"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.concatHighlightedParts = concatHighlightedParts;
var _escapeHighlight = require("./escape-highlight");
function concatHighlightedParts(parts) {
  var highlightPreTag = _escapeHighlight.TAG_REPLACEMENT.highlightPreTag,
    highlightPostTag = _escapeHighlight.TAG_REPLACEMENT.highlightPostTag;
  return parts.map(function (part) {
    return part.isHighlighted ? highlightPreTag + part.value + highlightPostTag : part.value;
  }).join('');
}