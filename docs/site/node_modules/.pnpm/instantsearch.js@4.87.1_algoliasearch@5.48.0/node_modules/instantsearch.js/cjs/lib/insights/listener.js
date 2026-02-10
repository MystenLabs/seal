"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.createInsightsEventHandler = void 0;
exports.default = withInsightsListener;
var _preact = require("preact");
var _insights = require("../../helpers/insights");
var _utils = require("../utils");
var createInsightsEventHandler = exports.createInsightsEventHandler = function createInsightsEventHandler(_ref) {
  var insights = _ref.insights,
    sendEvent = _ref.sendEvent;
  return function (event) {
    // new way, e.g. bindEvent("click", hit, "Hit clicked")
    var insightsThroughSendEvent = findInsightsTarget(event.target, event.currentTarget, function (element) {
      return element.hasAttribute('data-insights-event');
    });
    if (insightsThroughSendEvent) {
      var payload = parseInsightsEvent(insightsThroughSendEvent);
      payload.forEach(function (single) {
        return sendEvent(single);
      });
    }

    // old way, e.g. instantsearch.insights("clickedObjectIDsAfterSearch", { .. })
    var insightsThroughFunction = findInsightsTarget(event.target, event.currentTarget, function (element) {
      return element.hasAttribute('data-insights-method') && element.hasAttribute('data-insights-payload');
    });
    if (insightsThroughFunction) {
      var _readDataAttributes = (0, _insights.readDataAttributes)(insightsThroughFunction),
        method = _readDataAttributes.method,
        _payload = _readDataAttributes.payload;
      insights(method, _payload);
    }
  };
};
function findInsightsTarget(startElement, endElement, validator) {
  var element = startElement;
  while (element && !validator(element)) {
    if (element === endElement) {
      return null;
    }
    element = element.parentElement;
  }
  return element;
}
function parseInsightsEvent(element) {
  var serializedPayload = element.getAttribute('data-insights-event');
  if (typeof serializedPayload !== 'string') {
    throw new Error('The insights middleware expects `data-insights-event` to be a base64-encoded JSON string.');
  }
  try {
    return (0, _utils.deserializePayload)(serializedPayload);
  } catch (error) {
    throw new Error('The insights middleware was unable to parse `data-insights-event`.');
  }
}

/**
 * @deprecated use `sendEvent` directly instead
 */
function withInsightsListener(BaseComponent) {
  process.env.NODE_ENV === 'development' ? (0, _utils.warning)(false, 'The `withInsightsListener` function is deprecated and will be removed in the next major version. Please use `sendEvent` directly instead.') : void 0;
  return function WithInsightsListener(props) {
    var handleClick = createInsightsEventHandler(props);
    return (0, _preact.h)("div", {
      onClick: handleClick
    }, (0, _preact.h)(BaseComponent, props));
  };
}