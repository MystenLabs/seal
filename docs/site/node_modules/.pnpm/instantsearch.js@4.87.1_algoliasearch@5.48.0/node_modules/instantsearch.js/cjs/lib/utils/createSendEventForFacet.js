"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.createSendEventForFacet = createSendEventForFacet;
var _isFacetRefined = require("./isFacetRefined");
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function _slicedToArray(r, e) { return _arrayWithHoles(r) || _iterableToArrayLimit(r, e) || _unsupportedIterableToArray(r, e) || _nonIterableRest(); }
function _nonIterableRest() { throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
function _iterableToArrayLimit(r, l) { var t = null == r ? null : "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"]; if (null != t) { var e, n, i, u, a = [], f = !0, o = !1; try { if (i = (t = t.call(r)).next, 0 === l) { if (Object(t) !== t) return; f = !1; } else for (; !(f = (e = i.call(t)).done) && (a.push(e.value), a.length !== l); f = !0); } catch (r) { o = !0, n = r; } finally { try { if (!f && null != t.return && (u = t.return(), Object(u) !== u)) return; } finally { if (o) throw n; } } return a; } }
function _arrayWithHoles(r) { if (Array.isArray(r)) return r; }
function createSendEventForFacet(_ref) {
  var instantSearchInstance = _ref.instantSearchInstance,
    helper = _ref.helper,
    attr = _ref.attribute,
    widgetType = _ref.widgetType;
  var sendEventForFacet = function sendEventForFacet() {
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }
    var facetValue = args[1],
      _args$ = args[2],
      eventName = _args$ === void 0 ? 'Filter Applied' : _args$,
      _args$2 = args[3],
      additionalData = _args$2 === void 0 ? {} : _args$2;
    var _args$0$split = args[0].split(':'),
      _args$0$split2 = _slicedToArray(_args$0$split, 2),
      eventType = _args$0$split2[0],
      eventModifier = _args$0$split2[1];
    var attribute = typeof attr === 'string' ? attr : attr(facetValue);
    if (args.length === 1 && _typeof(args[0]) === 'object') {
      instantSearchInstance.sendEventToInsights(args[0]);
    } else if (eventType === 'click' && args.length >= 2 && args.length <= 4) {
      if (!(0, _isFacetRefined.isFacetRefined)(helper, attribute, facetValue)) {
        var _helper$lastResults;
        // send event only when the facet is being checked "ON"
        instantSearchInstance.sendEventToInsights({
          insightsMethod: 'clickedFilters',
          widgetType: widgetType,
          eventType: eventType,
          eventModifier: eventModifier,
          payload: _objectSpread({
            eventName: eventName,
            index: ((_helper$lastResults = helper.lastResults) === null || _helper$lastResults === void 0 ? void 0 : _helper$lastResults.index) || helper.state.index,
            filters: ["".concat(attribute, ":").concat(facetValue)]
          }, additionalData),
          attribute: attribute
        });
      }
    } else if (process.env.NODE_ENV === 'development') {
      throw new Error("You need to pass between two and four arguments like:\n  sendEvent('click', facetValue, eventName?, additionalData?);\n\nIf you want to send a custom payload, you can pass one object: sendEvent(customPayload);\n");
    }
  };
  return sendEventForFacet;
}