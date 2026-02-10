function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
import { warning, serializePayload, deserializePayload } from "../lib/utils/index.js";
/** @deprecated use bindEvent instead */
export function readDataAttributes(domElement) {
  var method = domElement.getAttribute('data-insights-method');
  var serializedPayload = domElement.getAttribute('data-insights-payload');
  if (typeof serializedPayload !== 'string') {
    throw new Error('The insights helper expects `data-insights-payload` to be a base64-encoded JSON string.');
  }
  try {
    var payload = deserializePayload(serializedPayload);
    return {
      method: method,
      payload: payload
    };
  } catch (error) {
    throw new Error('The insights helper was unable to parse `data-insights-payload`.');
  }
}

/** @deprecated use bindEvent instead */
export function writeDataAttributes(_ref) {
  var method = _ref.method,
    payload = _ref.payload;
  if (_typeof(payload) !== 'object') {
    throw new Error("The insights helper expects the payload to be an object.");
  }
  var serializedPayload;
  try {
    serializedPayload = serializePayload(payload);
  } catch (error) {
    throw new Error("Could not JSON serialize the payload object.");
  }
  return "data-insights-method=\"".concat(method, "\" data-insights-payload=\"").concat(serializedPayload, "\"");
}

/**
 * @deprecated This function will be still supported in 4.x releases, but not further. It is replaced by the `insights` middleware. For more information, visit https://www.algolia.com/doc/guides/getting-insights-and-analytics/search-analytics/click-through-and-conversions/how-to/send-click-and-conversion-events-with-instantsearch/js/
 */
export default function insights(method, payload) {
  process.env.NODE_ENV === 'development' ? warning(false, "`insights` function has been deprecated. It is still supported in 4.x releases, but not further. It is replaced by the `insights` middleware.\n\nFor more information, visit https://www.algolia.com/doc/guides/getting-insights-and-analytics/search-analytics/click-through-and-conversions/how-to/send-click-and-conversion-events-with-instantsearch/js/") : void 0;
  return writeDataAttributes({
    method: method,
    payload: payload
  });
}