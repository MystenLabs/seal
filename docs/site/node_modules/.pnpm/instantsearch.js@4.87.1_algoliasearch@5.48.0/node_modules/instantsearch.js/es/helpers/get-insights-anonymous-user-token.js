function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
import { warning } from "../lib/utils/index.js";
export var ANONYMOUS_TOKEN_COOKIE_KEY = '_ALGOLIA';
function getCookie(name) {
  if ((typeof document === "undefined" ? "undefined" : _typeof(document)) !== 'object' || typeof document.cookie !== 'string') {
    return undefined;
  }
  var prefix = "".concat(name, "=");
  var cookies = document.cookie.split(';');
  for (var i = 0; i < cookies.length; i++) {
    var cookie = cookies[i];
    while (cookie.charAt(0) === ' ') {
      cookie = cookie.substring(1);
    }
    if (cookie.indexOf(prefix) === 0) {
      return cookie.substring(prefix.length, cookie.length);
    }
  }
  return undefined;
}
export function getInsightsAnonymousUserTokenInternal() {
  return getCookie(ANONYMOUS_TOKEN_COOKIE_KEY);
}

/**
 * @deprecated This function will be still supported in 4.x releases, but not further. It is replaced by the `insights` middleware. For more information, visit https://www.algolia.com/doc/guides/getting-insights-and-analytics/search-analytics/click-through-and-conversions/how-to/send-click-and-conversion-events-with-instantsearch/js/
 */
export default function getInsightsAnonymousUserToken() {
  process.env.NODE_ENV === 'development' ? warning(false, "`getInsightsAnonymousUserToken` function has been deprecated. It is still supported in 4.x releases, but not further. It is replaced by the `insights` middleware.\n\nFor more information, visit https://www.algolia.com/doc/guides/getting-insights-and-analytics/search-analytics/click-through-and-conversions/how-to/send-click-and-conversion-events-with-instantsearch/js/") : void 0;
  return getInsightsAnonymousUserTokenInternal();
}