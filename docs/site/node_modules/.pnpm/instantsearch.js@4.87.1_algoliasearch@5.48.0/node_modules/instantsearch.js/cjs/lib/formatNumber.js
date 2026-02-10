"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.formatNumber = formatNumber;
function formatNumber(value, numberLocale) {
  return value.toLocaleString(numberLocale);
}