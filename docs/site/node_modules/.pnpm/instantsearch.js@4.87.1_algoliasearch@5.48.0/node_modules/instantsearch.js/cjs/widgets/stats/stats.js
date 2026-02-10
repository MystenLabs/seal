"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.defaultTemplates = exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _Stats = _interopRequireDefault(require("../../components/Stats/Stats"));
var _connectStats = _interopRequireDefault(require("../../connectors/stats/connectStats"));
var _formatNumber = require("../../lib/formatNumber");
var _suit = require("../../lib/suit");
var _templating = require("../../lib/templating");
var _utils = require("../../lib/utils");
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'stats'
});
var suit = (0, _suit.component)('Stats');
var defaultTemplates = exports.defaultTemplates = {
  text: function text(props) {
    return "".concat(props.areHitsSorted ? getSortedResultsSentence(props) : getResultsSentence(props), " found in ").concat(props.processingTimeMS, "ms");
  }
};
function getSortedResultsSentence(_ref) {
  var nbHits = _ref.nbHits,
    hasNoSortedResults = _ref.hasNoSortedResults,
    hasOneSortedResults = _ref.hasOneSortedResults,
    hasManySortedResults = _ref.hasManySortedResults,
    nbSortedHits = _ref.nbSortedHits;
  var suffix = "sorted out of ".concat((0, _formatNumber.formatNumber)(nbHits));
  if (hasNoSortedResults) {
    return "No relevant results ".concat(suffix);
  }
  if (hasOneSortedResults) {
    return "1 relevant result ".concat(suffix);
  }
  if (hasManySortedResults) {
    return "".concat((0, _formatNumber.formatNumber)(nbSortedHits || 0), " relevant results ").concat(suffix);
  }
  return '';
}
function getResultsSentence(_ref2) {
  var nbHits = _ref2.nbHits,
    hasNoResults = _ref2.hasNoResults,
    hasOneResult = _ref2.hasOneResult,
    hasManyResults = _ref2.hasManyResults;
  if (hasNoResults) {
    return 'No results';
  }
  if (hasOneResult) {
    return '1 result';
  }
  if (hasManyResults) {
    return "".concat((0, _formatNumber.formatNumber)(nbHits), " results");
  }
  return '';
}
var renderer = function renderer(_ref3) {
  var renderState = _ref3.renderState,
    cssClasses = _ref3.cssClasses,
    containerNode = _ref3.containerNode,
    templates = _ref3.templates;
  return function (_ref4, isFirstRendering) {
    var hitsPerPage = _ref4.hitsPerPage,
      nbHits = _ref4.nbHits,
      nbSortedHits = _ref4.nbSortedHits,
      areHitsSorted = _ref4.areHitsSorted,
      nbPages = _ref4.nbPages,
      page = _ref4.page,
      processingTimeMS = _ref4.processingTimeMS,
      query = _ref4.query,
      instantSearchInstance = _ref4.instantSearchInstance;
    if (isFirstRendering) {
      renderState.templateProps = (0, _templating.prepareTemplateProps)({
        defaultTemplates: defaultTemplates,
        templatesConfig: instantSearchInstance.templatesConfig,
        templates: templates
      });
      return;
    }
    (0, _preact.render)((0, _preact.h)(_Stats.default, {
      cssClasses: cssClasses,
      hitsPerPage: hitsPerPage,
      nbHits: nbHits,
      nbSortedHits: nbSortedHits,
      areHitsSorted: areHitsSorted,
      nbPages: nbPages,
      page: page,
      processingTimeMS: processingTimeMS,
      query: query,
      templateProps: renderState.templateProps
    }), containerNode);
  };
};

/**
 * The `stats` widget is used to display useful insights about the current results.
 *
 * By default, it will display the **number of hits** and the time taken to compute the
 * results inside the engine.
 */
var stats = function stats(widgetParams) {
  var _ref5 = widgetParams || {},
    container = _ref5.container,
    _ref5$cssClasses = _ref5.cssClasses,
    userCssClasses = _ref5$cssClasses === void 0 ? {} : _ref5$cssClasses,
    _ref5$templates = _ref5.templates,
    templates = _ref5$templates === void 0 ? {} : _ref5$templates;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var containerNode = (0, _utils.getContainerNode)(container);
  var cssClasses = {
    root: (0, _instantsearchUiComponents.cx)(suit(), userCssClasses.root),
    text: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'text'
    }), userCssClasses.text)
  };
  var specializedRenderer = renderer({
    containerNode: containerNode,
    cssClasses: cssClasses,
    templates: templates,
    renderState: {}
  });
  var makeWidget = (0, _connectStats.default)(specializedRenderer, function () {
    return (0, _preact.render)(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({})), {}, {
    $$widgetType: 'ais.stats'
  });
};
var _default = exports.default = stats;