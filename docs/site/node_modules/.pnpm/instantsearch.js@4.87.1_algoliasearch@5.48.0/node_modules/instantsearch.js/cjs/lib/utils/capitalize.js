"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.capitalize = capitalize;
function capitalize(text) {
  return text.toString().charAt(0).toUpperCase() + text.toString().slice(1);
}