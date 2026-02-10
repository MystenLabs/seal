function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
import { cx } from 'instantsearch-ui-components';
import { h, render } from 'preact';
import InfiniteHits from "../../components/InfiniteHits/InfiniteHits.js";
import connectInfiniteHits from "../../connectors/infinite-hits/connectInfiniteHits.js";
import { withInsights } from "../../lib/insights/index.js";
import { component } from "../../lib/suit.js";
import { prepareTemplateProps } from "../../lib/templating/index.js";
import { getContainerNode, createDocumentationMessageGenerator } from "../../lib/utils/index.js";
import defaultTemplates from "./defaultTemplates.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'infinite-hits'
});
var suit = component('InfiniteHits');
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
      renderState.templateProps = prepareTemplateProps({
        defaultTemplates: defaultTemplates,
        templatesConfig: instantSearchInstance.templatesConfig,
        templates: templates
      });
      return;
    }
    render(h(InfiniteHits, {
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
export default (function infiniteHits(widgetParams) {
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
  var containerNode = getContainerNode(container);
  var cssClasses = {
    root: cx(suit(), userCssClasses.root),
    emptyRoot: cx(suit({
      modifierName: 'empty'
    }), userCssClasses.emptyRoot),
    item: cx(suit({
      descendantName: 'item'
    }), userCssClasses.item),
    list: cx(suit({
      descendantName: 'list'
    }), userCssClasses.list),
    loadPrevious: cx(suit({
      descendantName: 'loadPrevious'
    }), userCssClasses.loadPrevious),
    disabledLoadPrevious: cx(suit({
      descendantName: 'loadPrevious',
      modifierName: 'disabled'
    }), userCssClasses.disabledLoadPrevious),
    loadMore: cx(suit({
      descendantName: 'loadMore'
    }), userCssClasses.loadMore),
    disabledLoadMore: cx(suit({
      descendantName: 'loadMore',
      modifierName: 'disabled'
    }), userCssClasses.disabledLoadMore),
    bannerRoot: cx(suit({
      descendantName: 'banner'
    }), userCssClasses.bannerRoot),
    bannerImage: cx(suit({
      descendantName: 'banner-image'
    }), userCssClasses.bannerImage),
    bannerLink: cx(suit({
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
  var makeWidget = withInsights(connectInfiniteHits)(specializedRenderer, function () {
    return render(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    escapeHTML: escapeHTML,
    transformItems: transformItems,
    showPrevious: showPrevious,
    cache: cache
  })), {}, {
    $$widgetType: 'ais.infiniteHits'
  });
});