import { checkIndexUiState } from "./checkIndexUiState.js";
import { isIndexWidget } from "./isIndexWidget.js";
export function setIndexHelperState(finalUiState, indexWidget) {
  var nextIndexUiState = finalUiState[indexWidget.getIndexId()] || {};
  if (process.env.NODE_ENV === 'development') {
    checkIndexUiState({
      index: indexWidget,
      indexUiState: nextIndexUiState
    });
  }
  indexWidget.getHelper().setState(indexWidget.getWidgetSearchParameters(indexWidget.getHelper().state, {
    uiState: nextIndexUiState
  }));
  indexWidget.getWidgets().filter(isIndexWidget).forEach(function (widget) {
    return setIndexHelperState(finalUiState, widget);
  });
}