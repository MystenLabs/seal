"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.toArray = toArray;
function toArray(value) {
  return Array.isArray(value) ? value : [value];
}