"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
Object.defineProperty(exports, "createInfiniteHitsSessionStorageCache", {
  enumerable: true,
  get: function get() {
    return _sessionStorage.default;
  }
});
var _sessionStorage = _interopRequireDefault(require("./sessionStorage"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }