"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.debounce = debounce;
// Debounce a function call to the trailing edge.
// The debounced function returns a promise.
function debounce(func, wait) {
  var lastTimeout = null;
  return function () {
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }
    return new Promise(function (resolve, reject) {
      if (lastTimeout) {
        clearTimeout(lastTimeout);
      }
      lastTimeout = setTimeout(function () {
        lastTimeout = null;
        Promise.resolve(func.apply(void 0, args)).then(resolve).catch(reject);
      }, wait);
    });
  };
}