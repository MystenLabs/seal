"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getObjectType = getObjectType;
function getObjectType(object) {
  return Object.prototype.toString.call(object).slice(8, -1);
}