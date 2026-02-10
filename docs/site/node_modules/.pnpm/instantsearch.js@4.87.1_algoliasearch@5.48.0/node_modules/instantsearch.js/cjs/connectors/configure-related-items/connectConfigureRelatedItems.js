"use strict";

function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _algoliasearchHelper = _interopRequireDefault(require("algoliasearch-helper"));
var _utils = require("../../lib/utils");
var _connectConfigure = _interopRequireDefault(require("../configure/connectConfigure"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _toConsumableArray(r) { return _arrayWithoutHoles(r) || _iterableToArray(r) || _unsupportedIterableToArray(r) || _nonIterableSpread(); }
function _nonIterableSpread() { throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _iterableToArray(r) { if ("undefined" != typeof Symbol && null != r[Symbol.iterator] || null != r["@@iterator"]) return Array.from(r); }
function _arrayWithoutHoles(r) { if (Array.isArray(r)) return _arrayLikeToArray(r); }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'configure-related-items',
  connector: true
});
function createOptionalFilter(_ref) {
  var attributeName = _ref.attributeName,
    attributeValue = _ref.attributeValue,
    attributeScore = _ref.attributeScore;
  return "".concat(attributeName, ":").concat(attributeValue, "<score=").concat(attributeScore || 1, ">");
}
var connectConfigureRelatedItems = function connectConfigureRelatedItems(renderFn, unmountFn) {
  return function (widgetParams) {
    var _ref2 = widgetParams || {},
      hit = _ref2.hit,
      matchingPatterns = _ref2.matchingPatterns,
      _ref2$transformSearch = _ref2.transformSearchParameters,
      transformSearchParameters = _ref2$transformSearch === void 0 ? function (x) {
        return x;
      } : _ref2$transformSearch;
    if (!hit) {
      throw new Error(withUsage('The `hit` option is required.'));
    }
    if (!matchingPatterns) {
      throw new Error(withUsage('The `matchingPatterns` option is required.'));
    }
    var optionalFilters = Object.keys(matchingPatterns).reduce(function (acc, attributeName) {
      var attribute = matchingPatterns[attributeName];
      var attributeValue = (0, _utils.getPropertyByPath)(hit, attributeName);
      var attributeScore = attribute.score;
      if (Array.isArray(attributeValue)) {
        return [].concat(_toConsumableArray(acc), [attributeValue.map(function (attributeSubValue) {
          return createOptionalFilter({
            attributeName: attributeName,
            attributeValue: attributeSubValue,
            attributeScore: attributeScore
          });
        })]);
      }
      if (typeof attributeValue === 'string') {
        return [].concat(_toConsumableArray(acc), [createOptionalFilter({
          attributeName: attributeName,
          attributeValue: attributeValue,
          attributeScore: attributeScore
        })]);
      }
      process.env.NODE_ENV === 'development' ? (0, _utils.warning)(false, "\nThe `matchingPatterns` option returned a value of type ".concat((0, _utils.getObjectType)(attributeValue), " for the \"").concat(attributeName, "\" key. This value was not sent to Algolia because `optionalFilters` only supports strings and array of strings.\n\nYou can remove the \"").concat(attributeName, "\" key from the `matchingPatterns` option.\n\nSee https://www.algolia.com/doc/api-reference/api-parameters/optionalFilters/\n            ")) : void 0;
      return acc;
    }, []);
    var searchParameters = _objectSpread({}, transformSearchParameters(new _algoliasearchHelper.default.SearchParameters({
      sumOrFiltersScores: true,
      facetFilters: ["objectID:-".concat(hit.objectID)],
      optionalFilters: optionalFilters
    })));
    var makeWidget = (0, _connectConfigure.default)(renderFn, unmountFn);
    return _objectSpread(_objectSpread({}, makeWidget({
      searchParameters: searchParameters
    })), {}, {
      $$type: 'ais.configureRelatedItems'
    });
  };
};

/** @deprecated use connectRelatedItems instead */
var _default = exports.default = connectConfigureRelatedItems;