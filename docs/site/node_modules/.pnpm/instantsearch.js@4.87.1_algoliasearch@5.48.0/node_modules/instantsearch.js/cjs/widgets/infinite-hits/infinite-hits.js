"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _InfiniteHits = _interopRequireDefault(require("../../components/InfiniteHits/InfiniteHits"));
var _connectInfiniteHits = _interopRequireDefault(require("../../connectors/infinite-hits/connectInfiniteHits"));
var _insights = require("../../lib/insights");
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
  name: 'infinite-hits'
});
var suit = (0, _suit.component)('InfiniteHits');
var renderer = function renderer(_ref) {
  var containerNode = _ref.containerNode,
    cssClasses = _ref.cssClasses,
    renderState = _ref.renderState,
    templates = _ref.templates,
    hasShowPrevious = _ref.showPrevious;
  return function (_ref2, isFirstRendering) {
    var items = _ref2.items,
      results = _ref2.results,
      showMore = _ref2.showMore,
      showPrevious = _ref2.showPrevious,
      isFirstPage = _ref2.isFirstPage,
      isLastPage = _ref2.isLastPage,
      instantSearchInstance = _ref2.instantSearchInstance,
      insights = _ref2.insights,
      bindEvent = _ref2.bindEvent,
      sendEvent = _ref2.sendEvent,
      banner = _ref2.banner;
    if (isFirstRendering) {
      renderState.templateProps = (0, _templating.prepareTemplateProps)({
        defaultTemplates: _defaultTemplates.default,
        templatesConfig: instantSearchInstance.templatesConfig,
        templates: templates
      });
      return;
    }
    (0, _preact.render)((0, _preact.h)(_InfiniteHits.default, {
      cssClasses: cssClasses,
      hits: items,
      results: results,
      hasShowPrevious: hasShowPrevious,
      showPrevious: showPrevious,
      showMore: showMore,
      templateProps: renderState.templateProps,
      isFirstPage: isFirstPage,
      isLastPage: isLastPage,
      insights: insights,
      sendEvent: sendEvent,
      bindEvent: bindEvent,
      banner: banner
    }), containerNode);
  };
};
var infiniteHits = exports.default = function infiniteHits(widgetParams) {
  var _ref3 = widgetParams || {},
    container = _ref3.container,
    escapeHTML = _ref3.escapeHTML,
    transformItems = _ref3.transformItems,
    _ref3$templates = _ref3.templates,
    templates = _ref3$templates === void 0 ? {} : _ref3$templates,
    _ref3$cssClasses = _ref3.cssClasses,
    userCssClasses = _ref3$cssClasses === void 0 ? {} : _ref3$cssClasses,
    showPrevious = _ref3.showPrevious,
    cache = _ref3.cache;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var containerNode = (0, _utils.getContainerNode)(container);
  var cssClasses = {
    root: (0, _instantsearchUiComponents.cx)(suit(), userCssClasses.root),
    emptyRoot: (0, _instantsearchUiComponents.cx)(suit({
      modifierName: 'empty'
    }), userCssClasses.emptyRoot),
    item: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'item'
    }), userCssClasses.item),
    list: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'list'
    }), userCssClasses.list),
    loadPrevious: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'loadPrevious'
    }), userCssClasses.loadPrevious),
    disabledLoadPrevious: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'loadPrevious',
      modifierName: 'disabled'
    }), userCssClasses.disabledLoadPrevious),
    loadMore: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'loadMore'
    }), userCssClasses.loadMore),
    disabledLoadMore: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'loadMore',
      modifierName: 'disabled'
    }), userCssClasses.disabledLoadMore),
    bannerRoot: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'banner'
    }), userCssClasses.bannerRoot),
    bannerImage: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'banner-image'
    }), userCssClasses.bannerImage),
    bannerLink: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'banner-link'
    }), userCssClasses.bannerLink)
  };
  var specializedRenderer = renderer({
    containerNode: containerNode,
    cssClasses: cssClasses,
    templates: templates,
    showPrevious: showPrevious,
    renderState: {}
  });
  var makeWidget = (0, _insights.withInsights)(_connectInfiniteHits.default)(specializedRenderer, function () {
    return (0, _preact.render)(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    escapeHTML: escapeHTML,
    transformItems: transformItems,
    showPrevious: showPrevious,
    cache: cache
  })), {}, {
    $$widgetType: 'ais.infiniteHits'
  });
};