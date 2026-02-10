"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _ToggleRefinement = _interopRequireDefault(require("../../components/ToggleRefinement/ToggleRefinement"));
var _connectToggleRefinement = _interopRequireDefault(require("../../connectors/toggle-refinement/connectToggleRefinement"));
var _suit = require("../../lib/suit");
var _templating = require("../../lib/templating");
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
  name: 'toggle-refinement'
});
var suit = (0, _suit.component)('ToggleRefinement');
var renderer = function renderer(_ref) {
  var containerNode = _ref.containerNode,
    cssClasses = _ref.cssClasses,
    renderState = _ref.renderState,
    templates = _ref.templates;
  return function (_ref2, isFirstRendering) {
    var value = _ref2.value,
      refine = _ref2.refine,
      instantSearchInstance = _ref2.instantSearchInstance;
    if (isFirstRendering) {
      renderState.templateProps = (0, _templating.prepareTemplateProps)({
        defaultTemplates: _defaultTemplates.default,
        templatesConfig: instantSearchInstance.templatesConfig,
        templates: templates
      });
      return;
    }
    (0, _preact.render)((0, _preact.h)(_ToggleRefinement.default, {
      cssClasses: cssClasses,
      currentRefinement: value,
      templateProps: renderState.templateProps,
      refine: refine
    }), containerNode);
  };
};
/**
 * The toggleRefinement widget lets the user either:
 *  - switch between two values for a single facetted attribute (free_shipping / not_free_shipping)
 *  - toggleRefinement a faceted value on and off (only 'canon' for brands)
 *
 * This widget is particularly useful if you have a boolean value in the records.
 *
 * @requirements
 * The attribute passed to `attribute` must be declared as an
 * [attribute for faceting](https://www.algolia.com/doc/guides/searching/faceting/#declaring-attributes-for-faceting)
 * in your Algolia settings.
 */
var toggleRefinement = function toggleRefinement(widgetParams) {
  var _ref3 = widgetParams || {},
    container = _ref3.container,
    attribute = _ref3.attribute,
    _ref3$cssClasses = _ref3.cssClasses,
    userCssClasses = _ref3$cssClasses === void 0 ? {} : _ref3$cssClasses,
    _ref3$templates = _ref3.templates,
    templates = _ref3$templates === void 0 ? {} : _ref3$templates,
    _ref3$on = _ref3.on,
    on = _ref3$on === void 0 ? true : _ref3$on,
    off = _ref3.off;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var containerNode = (0, _utils.getContainerNode)(container);
  var cssClasses = {
    root: (0, _instantsearchUiComponents.cx)(suit(), userCssClasses.root),
    label: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'label'
    }), userCssClasses.label),
    checkbox: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'checkbox'
    }), userCssClasses.checkbox),
    labelText: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'labelText'
    }), userCssClasses.labelText)
  };
  var specializedRenderer = renderer({
    containerNode: containerNode,
    cssClasses: cssClasses,
    renderState: {},
    templates: templates
  });
  var makeWidget = (0, _connectToggleRefinement.default)(specializedRenderer, function () {
    return (0, _preact.render)(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    attribute: attribute,
    on: on,
    off: off
  })), {}, {
    $$widgetType: 'ais.toggleRefinement'
  });
};
var _default = exports.default = toggleRefinement;