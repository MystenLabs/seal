"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var defaultTemplates = {
  header: function header() {
    return '';
  },
  loader: function loader() {
    return '';
  },
  item: function item(_item) {
    return JSON.stringify(_item);
  }
};
var _default = exports.default = defaultTemplates;