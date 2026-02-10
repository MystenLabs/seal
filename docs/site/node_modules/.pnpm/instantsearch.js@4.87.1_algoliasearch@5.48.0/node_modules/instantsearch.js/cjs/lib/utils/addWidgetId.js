"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.addWidgetId = addWidgetId;
exports.resetWidgetId = resetWidgetId;
var id = 0;
function addWidgetId(widget) {
  if (widget.dependsOn !== 'recommend') {
    return;
  }
  widget.$$id = id++;
}
function resetWidgetId() {
  id = 0;
}