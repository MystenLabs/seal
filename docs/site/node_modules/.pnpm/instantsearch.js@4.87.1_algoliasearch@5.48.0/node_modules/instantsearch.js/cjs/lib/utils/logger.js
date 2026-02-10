"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.warning = exports.warn = exports.deprecate = void 0;
var _noop = require("./noop");
/**
 * Logs a warning when this function is called, in development environment only.
 */
var deprecate = exports.deprecate = function deprecate(fn, message) {
  return fn;
};

/**
 * Logs a warning
 * This is used to log issues in development environment only.
 */
var warn = exports.warn = _noop.noop;

/**
 * Logs a warning if the condition is not met.
 * This is used to log issues in development environment only.
 */
var _warning = exports.warning = _noop.noop;
if (process.env.NODE_ENV === 'development') {
  exports.warn = warn = function warn(message) {
    // eslint-disable-next-line no-console
    console.warn("[InstantSearch.js]: ".concat(message.trim()));
  };
  exports.deprecate = deprecate = function deprecate(fn, message) {
    var hasAlreadyPrinted = false;
    return function () {
      if (!hasAlreadyPrinted) {
        hasAlreadyPrinted = true;
        process.env.NODE_ENV === 'development' ? warn(message) : void 0;
      }
      return fn.apply(void 0, arguments);
    };
  };
  exports.warning = _warning = function warning(condition, message) {
    if (condition) {
      return;
    }
    var hasAlreadyPrinted = _warning.cache[message];
    if (!hasAlreadyPrinted) {
      _warning.cache[message] = true;
      process.env.NODE_ENV === 'development' ? warn(message) : void 0;
    }
  };
  _warning.cache = {};
}