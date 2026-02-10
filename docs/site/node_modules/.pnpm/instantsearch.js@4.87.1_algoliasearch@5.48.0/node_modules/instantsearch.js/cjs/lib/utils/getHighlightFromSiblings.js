"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getHighlightFromSiblings = getHighlightFromSiblings;
var _escapeHtml = require("./escape-html");
var hasAlphanumeric = new RegExp(/\w/i);
function getHighlightFromSiblings(parts, i) {
  var _parts, _parts2;
  var current = parts[i];
  var isNextHighlighted = ((_parts = parts[i + 1]) === null || _parts === void 0 ? void 0 : _parts.isHighlighted) || true;
  var isPreviousHighlighted = ((_parts2 = parts[i - 1]) === null || _parts2 === void 0 ? void 0 : _parts2.isHighlighted) || true;
  if (!hasAlphanumeric.test((0, _escapeHtml.unescape)(current.value)) && isPreviousHighlighted === isNextHighlighted) {
    return isPreviousHighlighted;
  }
  return current.isHighlighted;
}