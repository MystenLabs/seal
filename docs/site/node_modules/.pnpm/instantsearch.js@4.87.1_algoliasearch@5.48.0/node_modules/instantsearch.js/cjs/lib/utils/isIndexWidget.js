"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.isIndexWidget = isIndexWidget;
function isIndexWidget(widget) {
  return widget.$$type === 'ais.index';
}