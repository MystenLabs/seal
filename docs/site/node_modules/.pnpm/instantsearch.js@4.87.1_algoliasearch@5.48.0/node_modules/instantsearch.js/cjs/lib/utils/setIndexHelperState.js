"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.setIndexHelperState = setIndexHelperState;
var _checkIndexUiState = require("./checkIndexUiState");
var _isIndexWidget = require("./isIndexWidget");
function setIndexHelperState(finalUiState, indexWidget) {
  var nextIndexUiState = finalUiState[indexWidget.getIndexId()] || {};
  if (process.env.NODE_ENV === 'development') {
    (0, _checkIndexUiState.checkIndexUiState)({
      index: indexWidget,
      indexUiState: nextIndexUiState
    });
  }
  indexWidget.getHelper().setState(indexWidget.getWidgetSearchParameters(indexWidget.getHelper().state, {
    uiState: nextIndexUiState
  }));
  indexWidget.getWidgets().filter(_isIndexWidget.isIndexWidget).forEach(function (widget) {
    return setIndexHelperState(finalUiState, widget);
  });
}