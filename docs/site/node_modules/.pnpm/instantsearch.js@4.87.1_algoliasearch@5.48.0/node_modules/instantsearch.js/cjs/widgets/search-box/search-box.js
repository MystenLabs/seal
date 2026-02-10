"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _SearchBox = _interopRequireDefault(require("../../components/SearchBox/SearchBox"));
var _connectSearchBox = _interopRequireDefault(require("../../connectors/search-box/connectSearchBox"));
var _suit = require("../../lib/suit");
var _utils = require("../../lib/utils");
var _defaultTemplates = _interopRequireDefault(require("./defaultTemplates"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'search-box'
});
var suit = (0, _suit.component)('SearchBox');
var renderer = function renderer(_ref) {
  var containerNode = _ref.containerNode,
    cssClasses = _ref.cssClasses,
    placeholder = _ref.placeholder,
    templates = _ref.templates,
    autofocus = _ref.autofocus,
    searchAsYouType = _ref.searchAsYouType,
    ignoreCompositionEvents = _ref.ignoreCompositionEvents,
    showReset = _ref.showReset,
    showSubmit = _ref.showSubmit,
    showLoadingIndicator = _ref.showLoadingIndicator;
  return function (_ref2) {
    var refine = _ref2.refine,
      query = _ref2.query,
      isSearchStalled = _ref2.isSearchStalled;
    (0, _preact.render)((0, _preact.h)(_SearchBox.default, {
      query: query,
      placeholder: placeholder,
      autofocus: autofocus,
      refine: refine,
      searchAsYouType: searchAsYouType,
      ignoreCompositionEvents: ignoreCompositionEvents,
      templates: templates,
      showSubmit: showSubmit,
      showReset: showReset,
      showLoadingIndicator: showLoadingIndicator,
      isSearchStalled: isSearchStalled,
      cssClasses: cssClasses
    }), containerNode);
  };
};

/**
 * The searchbox widget is used to let the user set a text based query.
 *
 * This is usually the  main entry point to start the search in an instantsearch context. For that
 * reason is usually placed on top, and not hidden so that the user can start searching right
 * away.
 *
 */

var searchBox = function searchBox(widgetParams) {
  var _ref3 = widgetParams || {},
    container = _ref3.container,
    _ref3$placeholder = _ref3.placeholder,
    placeholder = _ref3$placeholder === void 0 ? '' : _ref3$placeholder,
    _ref3$cssClasses = _ref3.cssClasses,
    userCssClasses = _ref3$cssClasses === void 0 ? {} : _ref3$cssClasses,
    _ref3$autofocus = _ref3.autofocus,
    autofocus = _ref3$autofocus === void 0 ? false : _ref3$autofocus,
    _ref3$searchAsYouType = _ref3.searchAsYouType,
    searchAsYouType = _ref3$searchAsYouType === void 0 ? true : _ref3$searchAsYouType,
    _ref3$ignoreCompositi = _ref3.ignoreCompositionEvents,
    ignoreCompositionEvents = _ref3$ignoreCompositi === void 0 ? false : _ref3$ignoreCompositi,
    _ref3$showReset = _ref3.showReset,
    showReset = _ref3$showReset === void 0 ? true : _ref3$showReset,
    _ref3$showSubmit = _ref3.showSubmit,
    showSubmit = _ref3$showSubmit === void 0 ? true : _ref3$showSubmit,
    _ref3$showLoadingIndi = _ref3.showLoadingIndicator,
    showLoadingIndicator = _ref3$showLoadingIndi === void 0 ? true : _ref3$showLoadingIndi,
    queryHook = _ref3.queryHook,
    _ref3$templates = _ref3.templates,
    userTemplates = _ref3$templates === void 0 ? {} : _ref3$templates;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var containerNode = (0, _utils.getContainerNode)(container);
  var cssClasses = {
    root: (0, _instantsearchUiComponents.cx)(suit(), userCssClasses.root),
    form: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'form'
    }), userCssClasses.form),
    input: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'input'
    }), userCssClasses.input),
    submit: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'submit'
    }), userCssClasses.submit),
    submitIcon: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'submitIcon'
    }), userCssClasses.submitIcon),
    reset: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'reset'
    }), userCssClasses.reset),
    resetIcon: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'resetIcon'
    }), userCssClasses.resetIcon),
    loadingIndicator: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'loadingIndicator'
    }), userCssClasses.loadingIndicator),
    loadingIcon: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'loadingIcon'
    }), userCssClasses.loadingIcon)
  };
  var templates = _objectSpread(_objectSpread({}, _defaultTemplates.default), userTemplates);
  var specializedRenderer = renderer({
    containerNode: containerNode,
    cssClasses: cssClasses,
    placeholder: placeholder,
    templates: templates,
    autofocus: autofocus,
    searchAsYouType: searchAsYouType,
    ignoreCompositionEvents: ignoreCompositionEvents,
    showReset: showReset,
    showSubmit: showSubmit,
    showLoadingIndicator: showLoadingIndicator
  });
  var makeWidget = (0, _connectSearchBox.default)(specializedRenderer, function () {
    return (0, _preact.render)(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    queryHook: queryHook
  })), {}, {
    $$widgetType: 'ais.searchBox'
  });
};
var _default = exports.default = searchBox;