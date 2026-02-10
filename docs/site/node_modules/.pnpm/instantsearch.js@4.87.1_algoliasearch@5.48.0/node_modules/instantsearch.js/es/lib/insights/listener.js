import { h } from 'preact';
import { readDataAttributes } from "../../helpers/insights.js";
import { deserializePayload, warning } from "../utils/index.js";
export var createInsightsEventHandler = function createInsightsEventHandler(_ref) {
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
      var _readDataAttributes = readDataAttributes(insightsThroughFunction),
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
    return deserializePayload(serializedPayload);
  } catch (error) {
    throw new Error('The insights middleware was unable to parse `data-insights-event`.');
  }
}

/**
 * @deprecated use `sendEvent` directly instead
 */
export default function withInsightsListener(BaseComponent) {
  process.env.NODE_ENV === 'development' ? warning(false, 'The `withInsightsListener` function is deprecated and will be removed in the next major version. Please use `sendEvent` directly instead.') : void 0;
  return function WithInsightsListener(props) {
    var handleClick = createInsightsEventHandler(props);
    return h("div", {
      onClick: handleClick
    }, h(BaseComponent, props));
  };
}