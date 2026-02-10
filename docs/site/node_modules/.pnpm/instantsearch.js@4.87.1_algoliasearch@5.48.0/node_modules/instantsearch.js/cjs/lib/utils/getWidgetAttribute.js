"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getWidgetAttribute = getWidgetAttribute;
function getWidgetAttribute(widget, initOptions) {
  var _widget$getWidgetRend;
  var renderState = (_widget$getWidgetRend = widget.getWidgetRenderState) === null || _widget$getWidgetRend === void 0 ? void 0 : _widget$getWidgetRend.call(widget, initOptions);
  var attribute = null;
  if (renderState && renderState.widgetParams) {
    // casting as widgetParams is checked just before
    var widgetParams = renderState.widgetParams;
    if (widgetParams.attribute) {
      attribute = widgetParams.attribute;
    } else if (Array.isArray(widgetParams.attributes)) {
      attribute = widgetParams.attributes[0];
    }
  }
  if (typeof attribute !== 'string') {
    throw new Error("Could not find the attribute of the widget:\n\n".concat(JSON.stringify(widget), "\n\nPlease check whether the widget's getWidgetRenderState returns widgetParams.attribute correctly."));
  }
  return attribute;
}