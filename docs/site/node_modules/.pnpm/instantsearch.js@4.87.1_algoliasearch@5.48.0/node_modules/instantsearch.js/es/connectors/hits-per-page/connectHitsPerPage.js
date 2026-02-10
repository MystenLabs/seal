function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function _toConsumableArray(r) { return _arrayWithoutHoles(r) || _iterableToArray(r) || _unsupportedIterableToArray(r) || _nonIterableSpread(); }
function _nonIterableSpread() { throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _iterableToArray(r) { if ("undefined" != typeof Symbol && null != r[Symbol.iterator] || null != r["@@iterator"]) return Array.from(r); }
function _arrayWithoutHoles(r) { if (Array.isArray(r)) return _arrayLikeToArray(r); }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
import { checkRendering, warning, createDocumentationMessageGenerator, noop } from "../../lib/utils/index.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'hits-per-page',
  connector: true
});
var connectHitsPerPage = function connectHitsPerPage(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : noop;
  checkRendering(renderFn, withUsage());
  return function (widgetParams) {
    var _ref = widgetParams || {},
      userItems = _ref.items,
      _ref$transformItems = _ref.transformItems,
      transformItems = _ref$transformItems === void 0 ? function (items) {
        return items;
      } : _ref$transformItems;
    if (!Array.isArray(userItems)) {
      throw new Error(withUsage('The `items` option expects an array of objects.'));
    }
    var items = userItems;
    var defaultItems = items.filter(function (item) {
      return item.default === true;
    });
    if (defaultItems.length === 0) {
      throw new Error(withUsage("A default value must be specified in `items`."));
    }
    if (defaultItems.length > 1) {
      throw new Error(withUsage('More than one default value is specified in `items`.'));
    }
    var defaultItem = defaultItems[0];
    var normalizeItems = function normalizeItems(_ref2) {
      var hitsPerPage = _ref2.hitsPerPage;
      return items.map(function (item) {
        return _objectSpread(_objectSpread({}, item), {}, {
          isRefined: Number(item.value) === Number(hitsPerPage)
        });
      });
    };
    var connectorState = {
      getRefine: function getRefine(helper) {
        return function (value) {
          return !value && value !== 0 ? helper.setQueryParameter('hitsPerPage', undefined).search() : helper.setQueryParameter('hitsPerPage', value).search();
        };
      },
      createURLFactory: function createURLFactory(_ref3) {
        var state = _ref3.state,
          createURL = _ref3.createURL,
          getWidgetUiState = _ref3.getWidgetUiState,
          helper = _ref3.helper;
        return function (value) {
          return createURL(function (uiState) {
            return getWidgetUiState(uiState, {
              searchParameters: state.resetPage().setQueryParameter('hitsPerPage', !value && value !== 0 ? undefined : value),
              helper: helper
            });
          });
        };
      }
    };
    return {
      $$type: 'ais.hitsPerPage',
      init: function init(initOptions) {
        var state = initOptions.state,
          instantSearchInstance = initOptions.instantSearchInstance;
        var isCurrentInOptions = items.some(function (item) {
          return Number(state.hitsPerPage) === Number(item.value);
        });
        if (!isCurrentInOptions) {
          process.env.NODE_ENV === 'development' ? warning(state.hitsPerPage !== undefined, "\n`hitsPerPage` is not defined.\nThe option `hitsPerPage` needs to be set using the `configure` widget.\n\nLearn more: https://www.algolia.com/doc/api-reference/widgets/hits-per-page/js/\n            ") : void 0;
          process.env.NODE_ENV === 'development' ? warning(false, "\nThe `items` option of `hitsPerPage` does not contain the \"hits per page\" value coming from the state: ".concat(state.hitsPerPage, ".\n\nYou may want to add another entry to the `items` option with this value.")) : void 0;
          items = [
          // The helper will convert the empty string to `undefined`.
          {
            value: '',
            label: ''
          }].concat(_toConsumableArray(items));
        }
        renderFn(_objectSpread(_objectSpread({}, this.getWidgetRenderState(initOptions)), {}, {
          instantSearchInstance: instantSearchInstance
        }), true);
      },
      render: function render(initOptions) {
        var instantSearchInstance = initOptions.instantSearchInstance;
        renderFn(_objectSpread(_objectSpread({}, this.getWidgetRenderState(initOptions)), {}, {
          instantSearchInstance: instantSearchInstance
        }), false);
      },
      dispose: function dispose(_ref4) {
        var state = _ref4.state;
        unmountFn();
        return state.setQueryParameter('hitsPerPage', undefined);
      },
      getRenderState: function getRenderState(renderState, renderOptions) {
        return _objectSpread(_objectSpread({}, renderState), {}, {
          hitsPerPage: this.getWidgetRenderState(renderOptions)
        });
      },
      getWidgetRenderState: function getWidgetRenderState(_ref5) {
        var state = _ref5.state,
          results = _ref5.results,
          createURL = _ref5.createURL,
          helper = _ref5.helper;
        var canRefine = results ? results.nbHits > 0 : false;
        return {
          items: transformItems(normalizeItems(state), {
            results: results
          }),
          refine: connectorState.getRefine(helper),
          createURL: connectorState.createURLFactory({
            state: state,
            createURL: createURL,
            getWidgetUiState: this.getWidgetUiState,
            helper: helper
          }),
          hasNoResults: !canRefine,
          canRefine: canRefine,
          widgetParams: widgetParams
        };
      },
      getWidgetUiState: function getWidgetUiState(uiState, _ref6) {
        var searchParameters = _ref6.searchParameters;
        var hitsPerPage = searchParameters.hitsPerPage;
        if (hitsPerPage === undefined || hitsPerPage === defaultItem.value) {
          return uiState;
        }
        return _objectSpread(_objectSpread({}, uiState), {}, {
          hitsPerPage: hitsPerPage
        });
      },
      getWidgetSearchParameters: function getWidgetSearchParameters(searchParameters, _ref7) {
        var uiState = _ref7.uiState;
        return searchParameters.setQueryParameters({
          hitsPerPage: uiState.hitsPerPage || defaultItem.value
        });
      }
    };
  };
};
export default connectHitsPerPage;