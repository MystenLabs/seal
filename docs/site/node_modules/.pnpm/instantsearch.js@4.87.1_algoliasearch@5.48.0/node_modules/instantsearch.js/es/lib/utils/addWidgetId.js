var id = 0;
export function addWidgetId(widget) {
  if (widget.dependsOn !== 'recommend') {
    return;
  }
  widget.$$id = id++;
}
export function resetWidgetId() {
  id = 0;
}