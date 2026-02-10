"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.walkIndex = walkIndex;
var _isIndexWidget = require("./isIndexWidget");
/**
 * Recurse over all child indices
 */
function walkIndex(indexWidget, callback) {
  callback(indexWidget);
  indexWidget.getWidgets().forEach(function (widget) {
    if ((0, _isIndexWidget.isIndexWidget)(widget)) {
      walkIndex(widget, callback);
    }
  });
}