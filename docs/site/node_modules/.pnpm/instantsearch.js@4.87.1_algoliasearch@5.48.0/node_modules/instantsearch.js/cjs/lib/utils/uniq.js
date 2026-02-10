"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.uniq = uniq;
function uniq(array) {
  return array.filter(function (value, index, self) {
    return self.indexOf(value) === index;
  });
}