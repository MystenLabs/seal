"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = createInfiniteHitsSessionStorageCache;
var _utils = require("../utils");
var _excluded = ["page"];
function _objectWithoutProperties(e, t) { if (null == e) return {}; var o, r, i = _objectWithoutPropertiesLoose(e, t); if (Object.getOwnPropertySymbols) { var n = Object.getOwnPropertySymbols(e); for (r = 0; r < n.length; r++) o = n[r], -1 === t.indexOf(o) && {}.propertyIsEnumerable.call(e, o) && (i[o] = e[o]); } return i; }
function _objectWithoutPropertiesLoose(r, e) { if (null == r) return {}; var t = {}; for (var n in r) if ({}.hasOwnProperty.call(r, n)) { if (-1 !== e.indexOf(n)) continue; t[n] = r[n]; } return t; }
function getStateWithoutPage(state) {
  var _ref = state || {},
    page = _ref.page,
    rest = _objectWithoutProperties(_ref, _excluded);
  return rest;
}
function createInfiniteHitsSessionStorageCache() {
  var _ref2 = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {},
    key = _ref2.key;
  var KEY = ['ais.infiniteHits', key].filter(Boolean).join(':');
  return {
    read: function read(_ref3) {
      var state = _ref3.state;
      var sessionStorage = (0, _utils.safelyRunOnBrowser)(function (_ref4) {
        var window = _ref4.window;
        return window.sessionStorage;
      });
      if (!sessionStorage) {
        return null;
      }
      try {
        var cache = JSON.parse(
        // @ts-expect-error JSON.parse() requires a string, but it actually accepts null, too.
        sessionStorage.getItem(KEY));
        return cache && (0, _utils.isEqual)(cache.state, getStateWithoutPage(state)) ? cache.hits : null;
      } catch (error) {
        if (error instanceof SyntaxError) {
          try {
            sessionStorage.removeItem(KEY);
          } catch (err) {
            // do nothing
          }
        }
        return null;
      }
    },
    write: function write(_ref5) {
      var state = _ref5.state,
        hits = _ref5.hits;
      var sessionStorage = (0, _utils.safelyRunOnBrowser)(function (_ref6) {
        var window = _ref6.window;
        return window.sessionStorage;
      });
      if (!sessionStorage) {
        return;
      }
      try {
        sessionStorage.setItem(KEY, JSON.stringify({
          state: getStateWithoutPage(state),
          hits: hits
        }));
      } catch (error) {
        // do nothing
      }
    }
  };
}