"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _PoweredBy = _interopRequireDefault(require("../../components/PoweredBy/PoweredBy"));
var _connectPoweredBy = _interopRequireDefault(require("../../connectors/powered-by/connectPoweredBy"));
var _suit = require("../../lib/suit");
var _utils = require("../../lib/utils");
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
var suit = (0, _suit.component)('PoweredBy');
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'powered-by'
});
var renderer = function renderer(_ref) {
  var containerNode = _ref.containerNode,
    cssClasses = _ref.cssClasses;
  return function (_ref2, isFirstRendering) {
    var url = _ref2.url,
      widgetParams = _ref2.widgetParams;
    if (isFirstRendering) {
      var _widgetParams$theme = widgetParams.theme,
        theme = _widgetParams$theme === void 0 ? 'light' : _widgetParams$theme;
      (0, _preact.render)((0, _preact.h)(_PoweredBy.default, {
        cssClasses: cssClasses,
        url: url,
        theme: theme
      }), containerNode);
      return;
    }
  };
};
var poweredBy = function poweredBy(widgetParams) {
  var _ref3 = widgetParams || {},
    container = _ref3.container,
    _ref3$cssClasses = _ref3.cssClasses,
    userCssClasses = _ref3$cssClasses === void 0 ? {} : _ref3$cssClasses,
    _ref3$theme = _ref3.theme,
    theme = _ref3$theme === void 0 ? 'light' : _ref3$theme;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var containerNode = (0, _utils.getContainerNode)(container);
  var cssClasses = {
    root: (0, _instantsearchUiComponents.cx)(suit(), suit({
      modifierName: theme === 'dark' ? 'dark' : 'light'
    }), userCssClasses.root),
    link: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'link'
    }), userCssClasses.link),
    logo: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'logo'
    }), userCssClasses.logo)
  };
  var specializedRenderer = renderer({
    containerNode: containerNode,
    cssClasses: cssClasses
  });
  var makeWidget = (0, _connectPoweredBy.default)(specializedRenderer, function () {
    return (0, _preact.render)(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    theme: theme
  })), {}, {
    $$widgetType: 'ais.poweredBy'
  });
};
var _default = exports.default = poweredBy;