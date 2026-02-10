"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getInitialResults = getInitialResults;
exports.waitForResults = waitForResults;
var _utils = require("./utils");
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
/**
 * Waits for the results from the search instance to coordinate the next steps
 * in `getServerState()`.
 */
function waitForResults(search) {
  var skipRecommend = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;
  var helper = search.mainHelper;

  // Extract search parameters from the search client to use them
  // later during hydration.
  var requestParamsList;
  var client = helper.getClient();
  if (search.compositionID) {
    helper.setClient(_objectSpread(_objectSpread({}, client), {}, {
      search: function search(query) {
        requestParamsList = [query.requestBody.params];
        return client.search(query);
      }
    }));
  } else {
    helper.setClient(_objectSpread(_objectSpread({}, client), {}, {
      search: function search(queries) {
        requestParamsList = queries.map(function (_ref) {
          var params = _ref.params;
          return params;
        });
        return client.search(queries);
      }
    }));
  }
  if (search._hasSearchWidget) {
    if (search.compositionID) {
      helper.searchWithComposition();
    } else {
      helper.searchOnlyWithDerivedHelpers();
    }
  }
  !skipRecommend && search._hasRecommendWidget && helper.recommend();
  return new Promise(function (resolve, reject) {
    var searchResultsReceived = !search._hasSearchWidget;
    var recommendResultsReceived = !search._hasRecommendWidget || skipRecommend;
    // All derived helpers resolve in the same tick so we're safe only relying
    // on the first one.
    helper.derivedHelpers[0].on('result', function () {
      searchResultsReceived = true;
      if (recommendResultsReceived) {
        resolve(requestParamsList);
      }
    });
    helper.derivedHelpers[0].on('recommend:result', function () {
      recommendResultsReceived = true;
      if (searchResultsReceived) {
        resolve(requestParamsList);
      }
    });

    // However, we listen to errors that can happen on any derived helper because
    // any error is critical.
    helper.on('error', function (error) {
      reject(error);
    });
    search.on('error', function (error) {
      reject(error);
    });
    helper.derivedHelpers.forEach(function (derivedHelper) {
      return derivedHelper.on('error', function (error) {
        reject(error);
      });
    });
  });
}

/**
 * Walks the InstantSearch root index to construct the initial results.
 */
function getInitialResults(rootIndex,
/**
 * Search parameters sent to the search client,
 * returned by `waitForResults()`.
 */
requestParamsList) {
  var initialResults = {};
  var requestParamsIndex = 0;
  (0, _utils.walkIndex)(rootIndex, function (widget) {
    var _widget$getHelper;
    var searchResults = widget.getResults();
    var recommendResults = (_widget$getHelper = widget.getHelper()) === null || _widget$getHelper === void 0 ? void 0 : _widget$getHelper.lastRecommendResults;
    if (searchResults || recommendResults) {
      var _searchResults$_rawRe, _requestParams$, _requestParams$2;
      var resultsCount = (searchResults === null || searchResults === void 0 ? void 0 : (_searchResults$_rawRe = searchResults._rawResults) === null || _searchResults$_rawRe === void 0 ? void 0 : _searchResults$_rawRe.length) || 0;
      var requestParams = resultsCount ? requestParamsList === null || requestParamsList === void 0 ? void 0 : requestParamsList.slice(requestParamsIndex, requestParamsIndex + resultsCount) : [];
      requestParamsIndex += resultsCount;
      initialResults[widget.getIndexId()] = _objectSpread(_objectSpread(_objectSpread({}, searchResults && {
        state: _objectSpread(_objectSpread({}, searchResults._state), {}, {
          clickAnalytics: requestParams === null || requestParams === void 0 ? void 0 : (_requestParams$ = requestParams[0]) === null || _requestParams$ === void 0 ? void 0 : _requestParams$.clickAnalytics,
          userToken: requestParams === null || requestParams === void 0 ? void 0 : (_requestParams$2 = requestParams[0]) === null || _requestParams$2 === void 0 ? void 0 : _requestParams$2.userToken
        }),
        results: searchResults._rawResults
      }), recommendResults && {
        recommendResults: {
          // We have to stringify + parse because of some explicitly undefined values.
          params: JSON.parse(JSON.stringify(recommendResults._state.params)),
          results: recommendResults._rawResults
        }
      }), requestParams && {
        requestParams: requestParams
      });
    }
  });
  if (Object.keys(initialResults).length === 0) {
    throw new Error('The root index does not have any results. Make sure you have at least one widget that provides results.');
  }
  return initialResults;
}