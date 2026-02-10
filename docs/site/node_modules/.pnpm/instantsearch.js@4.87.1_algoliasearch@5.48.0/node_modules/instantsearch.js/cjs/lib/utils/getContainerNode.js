"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getContainerNode = getContainerNode;
var _isDomElement = require("./isDomElement");
/**
 * Return the container. If it's a string, it is considered a
 * css selector and retrieves the first matching element. Otherwise
 * test if it validates that it's a correct DOMElement.
 *
 * @param {string|HTMLElement} selectorOrHTMLElement CSS Selector or container node.
 * @return {HTMLElement} Container node
 * @throws Error when the type is not correct
 */
function getContainerNode(selectorOrHTMLElement) {
  var isSelectorString = typeof selectorOrHTMLElement === 'string';
  var domElement = isSelectorString ? document.querySelector(selectorOrHTMLElement) : selectorOrHTMLElement;
  if (!(0, _isDomElement.isDomElement)(domElement)) {
    var errorMessage = 'Container must be `string` or `HTMLElement`.';
    if (isSelectorString) {
      errorMessage += " Unable to find ".concat(selectorOrHTMLElement);
    }
    throw new Error(errorMessage);
  }
  return domElement;
}