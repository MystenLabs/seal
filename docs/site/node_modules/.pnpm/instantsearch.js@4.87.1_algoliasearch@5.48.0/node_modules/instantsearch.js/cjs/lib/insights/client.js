"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = withInsights;
exports.inferPayload = void 0;
var _utils = require("../utils");
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
var getSelectedHits = function getSelectedHits(hits, selectedObjectIDs) {
  return selectedObjectIDs.map(function (objectID) {
    var hit = (0, _utils.find)(hits, function (h) {
      return h.objectID === objectID;
    });
    if (typeof hit === 'undefined') {
      throw new Error("Could not find objectID \"".concat(objectID, "\" passed to `clickedObjectIDsAfterSearch` in the returned hits. This is necessary to infer the absolute position and the query ID."));
    }
    return hit;
  });
};
var getQueryID = function getQueryID(selectedHits) {
  var queryIDs = (0, _utils.uniq)(selectedHits.map(function (hit) {
    return hit.__queryID;
  }));
  if (queryIDs.length > 1) {
    throw new Error('Insights currently allows a single `queryID`. The `objectIDs` provided map to multiple `queryID`s.');
  }
  var queryID = queryIDs[0];
  if (typeof queryID !== 'string') {
    throw new Error("Could not infer `queryID`. Ensure InstantSearch `clickAnalytics: true` was added with the Configure widget.\n\nSee: https://alg.li/lNiZZ7");
  }
  return queryID;
};
var getPositions = function getPositions(selectedHits) {
  return selectedHits.map(function (hit) {
    return hit.__position;
  });
};
var inferPayload = exports.inferPayload = function inferPayload(_ref) {
  var method = _ref.method,
    results = _ref.results,
    hits = _ref.hits,
    objectIDs = _ref.objectIDs;
  var index = results.index;
  var selectedHits = getSelectedHits(hits, objectIDs);
  var queryID = getQueryID(selectedHits);
  switch (method) {
    case 'clickedObjectIDsAfterSearch':
      {
        var positions = getPositions(selectedHits);
        return {
          index: index,
          queryID: queryID,
          objectIDs: objectIDs,
          positions: positions
        };
      }
    case 'convertedObjectIDsAfterSearch':
      return {
        index: index,
        queryID: queryID,
        objectIDs: objectIDs
      };
    default:
      throw new Error("Unsupported method passed to insights: \"".concat(method, "\"."));
  }
};
var wrapInsightsClient = function wrapInsightsClient(aa, results, hits) {
  return function (method) {
    for (var _len = arguments.length, payloads = new Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
      payloads[_key - 1] = arguments[_key];
    }
    var payload = payloads[0];
    process.env.NODE_ENV === 'development' ? (0, _utils.warning)(false, "`insights` function has been deprecated. It is still supported in 4.x releases, but not further. It is replaced by the `insights` middleware.\n\nFor more information, visit https://www.algolia.com/doc/guides/getting-insights-and-analytics/search-analytics/click-through-and-conversions/how-to/send-click-and-conversion-events-with-instantsearch/js/") : void 0;
    if (!aa) {
      var withInstantSearchUsage = (0, _utils.createDocumentationMessageGenerator)({
        name: 'instantsearch'
      });
      throw new Error(withInstantSearchUsage('The `insightsClient` option has not been provided to `instantsearch`.'));
    }
    if (!Array.isArray(payload.objectIDs)) {
      throw new TypeError('Expected `objectIDs` to be an array.');
    }
    var inferredPayload = inferPayload({
      method: method,
      results: results,
      hits: hits,
      objectIDs: payload.objectIDs
    });
    aa(method, _objectSpread(_objectSpread({}, inferredPayload), payload));
  };
};

/**
 * @deprecated This function will be still supported in 4.x releases, but not further. It is replaced by the `insights` middleware. For more information, visit https://www.algolia.com/doc/guides/getting-insights-and-analytics/search-analytics/click-through-and-conversions/how-to/send-click-and-conversion-events-with-instantsearch/js/
 * It passes `insights` to `HitsWithInsightsListener` and `InfiniteHitsWithInsightsListener`.
 */
function withInsights(connector) {
  return function (renderFn, unmountFn) {
    return connector(function (renderOptions, isFirstRender) {
      var results = renderOptions.results,
        hits = renderOptions.hits,
        instantSearchInstance = renderOptions.instantSearchInstance;
      if (results && hits && instantSearchInstance) {
        var insights = wrapInsightsClient(instantSearchInstance.insightsClient, results, hits);
        return renderFn(_objectSpread(_objectSpread({}, renderOptions), {}, {
          insights: insights
        }), isFirstRender);
      }
      return renderFn(renderOptions, isFirstRender);
    }, unmountFn);
  };
}