"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.isPlainObject = isPlainObject;
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
/**
 * This implementation is taken from Lodash implementation.
 * See: https://github.com/lodash/lodash/blob/master/isPlainObject.js
 */

function getTag(value) {
  if (value === null) {
    return value === undefined ? '[object Undefined]' : '[object Null]';
  }
  return Object.prototype.toString.call(value);
}
function isObjectLike(value) {
  return _typeof(value) === 'object' && value !== null;
}

/**
 * Checks if `value` is a plain object.
 *
 * A plain object is an object created by the `Object`
 * constructor or with a `[[Prototype]]` of `null`.
 */
function isPlainObject(value) {
  if (!isObjectLike(value) || getTag(value) !== '[object Object]') {
    return false;
  }
  if (Object.getPrototypeOf(value) === null) {
    return true;
  }
  var proto = value;
  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto);
  }
  return Object.getPrototypeOf(value) === proto;
}