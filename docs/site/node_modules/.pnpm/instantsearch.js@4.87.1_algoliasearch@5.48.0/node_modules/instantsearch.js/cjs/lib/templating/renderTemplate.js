"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.renderTemplate = renderTemplate;
var _hogan = _interopRequireDefault(require("hogan.js"));
var _preact = require("htm/preact");
var _components = require("../../helpers/components");
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
// We add all our template helper methods to the template as lambdas. Note
// that lambdas in Mustache are supposed to accept a second argument of
// `render` to get the rendered value, not the literal `{{value}}`. But
// this is currently broken (see https://github.com/twitter/hogan.js/issues/222).
function transformHelpersToHogan() {
  var helpers = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
  var compileOptions = arguments.length > 1 ? arguments[1] : undefined;
  var data = arguments.length > 2 ? arguments[2] : undefined;
  return Object.keys(helpers).reduce(function (acc, helperKey) {
    return _objectSpread(_objectSpread({}, acc), {}, _defineProperty({}, helperKey, function () {
      var _this = this;
      return function (text) {
        var render = function render(value) {
          return _hogan.default.compile(value, compileOptions).render(_this);
        };
        return helpers[helperKey].call(data, text, render);
      };
    }));
  }, {});
}
function renderTemplate(_ref) {
  var templates = _ref.templates,
    templateKey = _ref.templateKey,
    compileOptions = _ref.compileOptions,
    helpers = _ref.helpers,
    data = _ref.data,
    bindEvent = _ref.bindEvent,
    sendEvent = _ref.sendEvent;
  var template = templates[templateKey];
  if (typeof template !== 'string' && typeof template !== 'function') {
    throw new Error("Template must be 'string' or 'function', was '".concat(_typeof(template), "' (key: ").concat(templateKey, ")"));
  }
  if (typeof template === 'function') {
    // @MAJOR no longer pass bindEvent when string templates are removed
    var params = bindEvent || {};
    params.html = _preact.html;
    params.sendEvent = sendEvent;
    params.components = {
      Highlight: _components.Highlight,
      ReverseHighlight: _components.ReverseHighlight,
      Snippet: _components.Snippet,
      ReverseSnippet: _components.ReverseSnippet
    };

    // @MAJOR remove the `as any` when string templates are removed
    // needed because not every template receives sendEvent
    return template(data, params);
  }
  var transformedHelpers = transformHelpersToHogan(helpers, compileOptions, data);
  return _hogan.default.compile(template, compileOptions).render(_objectSpread(_objectSpread({}, data), {}, {
    helpers: transformedHelpers
  })).replace(/[ \n\r\t\f\xA0]+/g, function (spaces) {
    return spaces.replace(/(^|\xA0+)[^\xA0]+/g, '$1 ');
  }).trim();
}