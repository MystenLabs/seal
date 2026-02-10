import { isIndexWidget } from "./isIndexWidget.js";
/**
 * Recurse over all child indices
 */
export function walkIndex(indexWidget, callback) {
  callback(indexWidget);
  indexWidget.getWidgets().forEach(function (widget) {
    if (isIndexWidget(widget)) {
      walkIndex(widget, callback);
    }
  });
}