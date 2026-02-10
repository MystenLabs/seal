"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _utils = require("../../lib/utils");
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
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'clear-refinements',
  connector: true
});
var connectClearRefinements = function connectClearRefinements(renderFn) {
  var unmountFn = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : _utils.noop;
  (0, _utils.checkRendering)(renderFn, withUsage());
  return function (widgetParams) {
    var _ref = widgetParams || {},
      _ref$includedAttribut = _ref.includedAttributes,
      includedAttributes = _ref$includedAttribut === void 0 ? [] : _ref$includedAttribut,
      _ref$excludedAttribut = _ref.excludedAttributes,
      excludedAttributes = _ref$excludedAttribut === void 0 ? ['query'] : _ref$excludedAttribut,
      _ref$transformItems = _ref.transformItems,
      transformItems = _ref$transformItems === void 0 ? function (items) {
        return items;
      } : _ref$transformItems;
    if (widgetParams && widgetParams.includedAttributes && widgetParams.excludedAttributes) {
      throw new Error(withUsage('The options `includedAttributes` and `excludedAttributes` cannot be used together.'));
    }
    var connectorState = {
      refine: _utils.noop,
      createURL: function createURL() {
        return '';
      },
      attributesToClear: []
    };
    var cachedRefine = function cachedRefine() {
      return connectorState.refine();
    };
    var cachedCreateURL = function cachedCreateURL() {
      return connectorState.createURL();
    };
    return {
      $$type: 'ais.clearRefinements',
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
      dispose: function dispose() {
        unmountFn();
      },
      getRenderState: function getRenderState(renderState, renderOptions) {
        return _objectSpread(_objectSpread({}, renderState), {}, {
          clearRefinements: this.getWidgetRenderState(renderOptions)
        });
      },
      getWidgetRenderState: function getWidgetRenderState(_ref2) {
        var createURL = _ref2.createURL,
          scopedResults = _ref2.scopedResults,
          results = _ref2.results;
        connectorState.attributesToClear = scopedResults.reduce(function (attributesToClear, scopedResult) {
          return attributesToClear.concat(getAttributesToClear({
            scopedResult: scopedResult,
            includedAttributes: includedAttributes,
            excludedAttributes: excludedAttributes,
            transformItems: transformItems,
            results: results
          }));
        }, []);
        connectorState.refine = function () {
          connectorState.attributesToClear.forEach(function (_ref3) {
            var indexHelper = _ref3.helper,
              items = _ref3.items;
            indexHelper.setState((0, _utils.clearRefinements)({
              helper: indexHelper,
              attributesToClear: items
            })).search();
          });
        };
        connectorState.createURL = function () {
          return createURL(_utils.mergeSearchParameters.apply(void 0, _toConsumableArray(connectorState.attributesToClear.map(function (_ref4) {
            var indexHelper = _ref4.helper,
              items = _ref4.items;
            return (0, _utils.clearRefinements)({
              helper: indexHelper,
              attributesToClear: items
            });
          }))));
        };
        var canRefine = connectorState.attributesToClear.some(function (attributeToClear) {
          return attributeToClear.items.length > 0;
        });
        return {
          canRefine: canRefine,
          hasRefinements: canRefine,
          refine: cachedRefine,
          createURL: cachedCreateURL,
          widgetParams: widgetParams
        };
      }
    };
  };
};
function getAttributesToClear(_ref5) {
  var scopedResult = _ref5.scopedResult,
    includedAttributes = _ref5.includedAttributes,
    excludedAttributes = _ref5.excludedAttributes,
    transformItems = _ref5.transformItems,
    results = _ref5.results;
  var includesQuery = includedAttributes.indexOf('query') !== -1 || excludedAttributes.indexOf('query') === -1;
  return {
    helper: scopedResult.helper,
    items: transformItems((0, _utils.uniq)((0, _utils.getRefinements)(scopedResult.results, scopedResult.helper.state, includesQuery).map(function (refinement) {
      return refinement.attribute;
    }).filter(function (attribute) {
      return (
        // If the array is empty (default case), we keep all the attributes
        includedAttributes.length === 0 ||
        // Otherwise, only add the specified attributes
        includedAttributes.indexOf(attribute) !== -1
      );
    }).filter(function (attribute) {
      return (
        // If the query is included, we ignore the default `excludedAttributes = ['query']`
        attribute === 'query' && includesQuery ||
        // Otherwise, ignore the excluded attributes
        excludedAttributes.indexOf(attribute) === -1
      );
    })), {
      results: results
    })
  };
}
var _default = exports.default = connectClearRefinements;