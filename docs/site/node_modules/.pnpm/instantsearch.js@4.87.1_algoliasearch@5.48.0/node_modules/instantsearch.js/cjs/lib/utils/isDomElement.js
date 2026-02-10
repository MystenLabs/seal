"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.isDomElement = isDomElement;
function isDomElement(object) {
  return object instanceof HTMLElement || Boolean(object) && object.nodeType > 0;
}