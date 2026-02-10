"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.safelyRunOnBrowser = safelyRunOnBrowser;
// eslint-disable-next-line no-restricted-globals

/**
 * Runs code on browser environments safely.
 */
function safelyRunOnBrowser(callback) {
  var _ref = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {
      fallback: function fallback() {
        return undefined;
      }
    },
    fallback = _ref.fallback;
  // eslint-disable-next-line no-restricted-globals
  if (typeof window === 'undefined') {
    return fallback();
  }

  // eslint-disable-next-line no-restricted-globals
  return callback({
    window: window
  });
}