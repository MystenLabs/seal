"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.hydrateSearchClient = hydrateSearchClient;
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function _slicedToArray(r, e) { return _arrayWithHoles(r) || _iterableToArrayLimit(r, e) || _unsupportedIterableToArray(r, e) || _nonIterableRest(); }
function _nonIterableRest() { throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
function _iterableToArrayLimit(r, l) { var t = null == r ? null : "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"]; if (null != t) { var e, n, i, u, a = [], f = !0, o = !1; try { if (i = (t = t.call(r)).next, 0 === l) { if (Object(t) !== t) return; f = !1; } else for (; !(f = (e = i.call(t)).done) && (a.push(e.value), a.length !== l); f = !0); } catch (r) { o = !0, n = r; } finally { try { if (!f && null != t.return && (u = t.return(), Object(u) !== u)) return; } finally { if (o) throw n; } } return a; } }
function _arrayWithHoles(r) { if (Array.isArray(r)) return r; }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function hydrateSearchClient(client, results) {
  if (!results) {
    return;
  }

  // Disable cache hydration on:
  // - Algoliasearch API Client < v4 with cache disabled
  // - Third party clients (detected by the `addAlgoliaAgent` function missing)

  if ((!('transporter' in client) || client._cacheHydrated) && (!client._useCache || typeof client.addAlgoliaAgent !== 'function')) {
    return;
  }
  var cachedRequest = [Object.keys(results).reduce(function (acc, key) {
    var _results$key = results[key],
      state = _results$key.state,
      requestParams = _results$key.requestParams,
      serverResults = _results$key.results;
    var mappedResults = serverResults && state ? serverResults.map(function (result, idx) {
      return _objectSpread({
        indexName: state.index || result.index
      }, requestParams !== null && requestParams !== void 0 && requestParams[idx] || result.params ? {
        params: serializeQueryParameters((requestParams === null || requestParams === void 0 ? void 0 : requestParams[idx]) || deserializeQueryParameters(result.params))
      } : {});
    }) : [];
    return acc.concat(mappedResults);
  }, [])];
  var cachedResults = Object.keys(results).reduce(function (acc, key) {
    var res = results[key].results;
    if (!res) {
      return acc;
    }
    return acc.concat(res);
  }, []);

  // Algoliasearch API Client >= v4
  // To hydrate the client we need to populate the cache with the data from
  // the server (done in `hydrateSearchClientWithMultiIndexRequest` or
  // `hydrateSearchClientWithSingleIndexRequest`). But since there is no way
  // for us to compute the key the same way as `algoliasearch-client` we need
  // to populate it on a custom key and override the `search` method to
  // search on it first.
  if ('transporter' in client && !client._cacheHydrated) {
    client._cacheHydrated = true;
    var baseMethod = client.search.bind(client);
    client.search = function (requests) {
      for (var _len = arguments.length, methodArgs = new Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
        methodArgs[_key - 1] = arguments[_key];
      }
      var requestsWithSerializedParams = Array.isArray(requests) ?
      // search client
      requests.map(function (request) {
        return _objectSpread(_objectSpread({}, request), {}, {
          params: serializeQueryParameters(request.params)
        });
      }) :
      // composition client
      serializeQueryParameters(requests.requestBody.params);
      return client.transporter.responsesCache.get({
        method: 'search',
        args: [requestsWithSerializedParams].concat(methodArgs)
      }, function () {
        return baseMethod.apply(void 0, [requests].concat(methodArgs));
      });
    };
    client.transporter.responsesCache.set({
      method: 'search',
      args: cachedRequest
    }, {
      results: cachedResults
    });
  }

  // Algoliasearch API Client < v4
  // Prior to client v4 we didn't have a proper API to hydrate the client
  // cache from the outside. The following code populates the cache with
  // a single-index result. You can find more information about the
  // computation of the key inside the client (see link below).
  // https://github.com/algolia/algoliasearch-client-javascript/blob/c27e89ff92b2a854ae6f40dc524bffe0f0cbc169/src/AlgoliaSearchCore.js#L232-L240
  if (!('transporter' in client)) {
    var cacheKey = "/1/indexes/*/queries_body_".concat(JSON.stringify({
      requests: cachedRequest
    }));
    client.cache = _objectSpread(_objectSpread({}, client.cache), {}, _defineProperty({}, cacheKey, JSON.stringify({
      results: Object.keys(results).map(function (key) {
        return results[key].results;
      })
    })));
  }
}
function deserializeQueryParameters(parameters) {
  return parameters.split('&').reduce(function (acc, parameter) {
    var _parameter$split = parameter.split('='),
      _parameter$split2 = _slicedToArray(_parameter$split, 2),
      key = _parameter$split2[0],
      value = _parameter$split2[1];
    acc[key] = value ? decodeURIComponent(value) : '';
    return acc;
  }, {});
}

// This function is copied from the algoliasearch v4 API Client. If modified,
// consider updating it also in `serializeQueryParameters` from `@algolia/transporter`.
function serializeQueryParameters(parameters) {
  var isObjectOrArray = function isObjectOrArray(value) {
    return Object.prototype.toString.call(value) === '[object Object]' || Object.prototype.toString.call(value) === '[object Array]';
  };
  var encode = function encode(format) {
    for (var _len2 = arguments.length, args = new Array(_len2 > 1 ? _len2 - 1 : 0), _key2 = 1; _key2 < _len2; _key2++) {
      args[_key2 - 1] = arguments[_key2];
    }
    var i = 0;
    return format.replace(/%s/g, function () {
      return encodeURIComponent(args[i++]);
    });
  };
  return Object.keys(parameters).map(function (key) {
    return encode('%s=%s', key, isObjectOrArray(parameters[key]) ? JSON.stringify(parameters[key]) : parameters[key]);
  }).join('&');
}