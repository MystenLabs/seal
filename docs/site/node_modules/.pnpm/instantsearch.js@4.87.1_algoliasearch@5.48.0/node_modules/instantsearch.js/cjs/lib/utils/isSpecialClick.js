"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.isSpecialClick = isSpecialClick;
function isSpecialClick(event) {
  var isMiddleClick = event.button === 1;
  return isMiddleClick || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey;
}