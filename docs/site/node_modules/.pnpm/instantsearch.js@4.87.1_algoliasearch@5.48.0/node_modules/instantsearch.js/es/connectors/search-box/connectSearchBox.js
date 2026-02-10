function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
import { checkRendering, createDocumentationMessageGenerator, noop } from "../../lib/utils/index.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'search-box',
  connector: true
});

/**
 * @typedef {Object} CustomSearchBoxWidgetParams
 * @property {function(string, function(string))} [queryHook = undefined] A function that will be called every time
 * a new value for the query is set. The first parameter is the query and the second is a
 * function to actually trigger the search. The function takes the query as the parameter.
 *
 * This queryHook can be used to debounce the number of searches done from the searchBox.
 */

var defaultQueryHook = function defaultQueryHook(query, hook) {
  return hook(query);
};

/**
 * **SearchBox** connector provides the logic to build a widget that will let the user search for a query.
 *
 * The connector provides to the rendering: `refine()` to set the query. The behaviour of this function
 * may be impacted by the `queryHook` widget parameter.
 */
var connectSearchBox = function connectSearchBox(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : noop;
  checkRendering(renderFn, withUsage());
  return function (widgetParams) {
    var _ref = widgetParams || {},
      _ref$queryHook = _ref.queryHook,
      queryHook = _ref$queryHook === void 0 ? defaultQueryHook : _ref$queryHook;
    var _refine;
    var _clear;
    return {
      $$type: 'ais.searchBox',
      init: function init(initOptions) {
        var instantSearchInstance = initOptions.instantSearchInstance;
        renderFn(_objectSpread(_objectSpread({}, this.getWidgetRenderState(initOptions)), {}, {
          instantSearchInstance: instantSearchInstance
        }), true);
      },
      render: function render(renderOptions) {
        var instantSearchInstance = renderOptions.instantSearchInstance;
        renderFn(_objectSpread(_objectSpread({}, this.getWidgetRenderState(renderOptions)), {}, {
          instantSearchInstance: instantSearchInstance
        }), false);
      },
      dispose: function dispose(_ref2) {
        var state = _ref2.state;
        unmountFn();
        return state.setQueryParameter('query', undefined);
      },
      getRenderState: function getRenderState(renderState, renderOptions) {
        return _objectSpread(_objectSpread({}, renderState), {}, {
          searchBox: this.getWidgetRenderState(renderOptions)
        });
      },
      getWidgetRenderState: function getWidgetRenderState(_ref3) {
        var helper = _ref3.helper,
          instantSearchInstance = _ref3.instantSearchInstance,
          state = _ref3.state;
        if (!_refine) {
          _refine = function _refine(query) {
            queryHook(query, function (q) {
              return helper.setQuery(q).search();
            });
          };
          _clear = function _clear() {
            helper.setQuery('').search();
          };
        }
        return {
          query: state.query || '',
          refine: _refine,
          clear: _clear,
          widgetParams: widgetParams,
          isSearchStalled: instantSearchInstance.status === 'stalled'
        };
      },
      getWidgetUiState: function getWidgetUiState(uiState, _ref4) {
        var searchParameters = _ref4.searchParameters;
        var query = searchParameters.query || '';
        if (query === '' || uiState && uiState.query === query) {
          return uiState;
        }
        return _objectSpread(_objectSpread({}, uiState), {}, {
          query: query
        });
      },
      getWidgetSearchParameters: function getWidgetSearchParameters(searchParameters, _ref5) {
        var uiState = _ref5.uiState;
        return searchParameters.setQueryParameter('query', uiState.query || '');
      }
    };
  };
};
export default connectSearchBox;