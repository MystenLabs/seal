function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
import { cx } from 'instantsearch-ui-components';
import { h } from 'preact';
import { createInsightsEventHandler } from "../../lib/insights/listener.js";
import { warning } from "../../lib/utils/index.js";
import Template from "../Template/Template.js";
var DefaultBanner = function DefaultBanner(_ref) {
  var banner = _ref.banner,
    classNames = _ref.classNames;
  if (!banner.image.urls[0].url) {
    return null;
  }
  return h("aside", {
    className: cx(classNames.bannerRoot)
  }, banner.link ? h("a", {
    className: cx(classNames.bannerLink),
    href: banner.link.url,
    target: banner.link.target
  }, h("img", {
    className: cx(classNames.bannerImage),
    src: banner.image.urls[0].url,
    alt: banner.image.title
  })) : h("img", {
    className: cx(classNames.bannerImage),
    src: banner.image.urls[0].url,
    alt: banner.image.title
  }));
};
var InfiniteHits = function InfiniteHits(_ref2) {
  var results = _ref2.results,
    hits = _ref2.hits,
    insights = _ref2.insights,
    bindEvent = _ref2.bindEvent,
    sendEvent = _ref2.sendEvent,
    hasShowPrevious = _ref2.hasShowPrevious,
    showPrevious = _ref2.showPrevious,
    showMore = _ref2.showMore,
    isFirstPage = _ref2.isFirstPage,
    isLastPage = _ref2.isLastPage,
    cssClasses = _ref2.cssClasses,
    templateProps = _ref2.templateProps,
    banner = _ref2.banner;
  var handleInsightsClick = createInsightsEventHandler({
    insights: insights,
    sendEvent: sendEvent
  });
  if (results.hits.length === 0) {
    return h("div", {
      className: cx(cssClasses.root, cssClasses.emptyRoot),
      onClick: handleInsightsClick
    }, banner && (templateProps.templates.banner ? h(Template, _extends({}, templateProps, {
      templateKey: "banner",
      rootTagName: "fragment",
      data: {
        banner: banner,
        className: cssClasses.bannerRoot
      }
    })) : h(DefaultBanner, {
      banner: banner,
      classNames: cssClasses
    })), h(Template, _extends({}, templateProps, {
      templateKey: "empty",
      rootTagName: "fragment",
      data: results
    })));
  }
  return h("div", {
    className: cssClasses.root
  }, hasShowPrevious && h(Template, _extends({}, templateProps, {
    templateKey: "showPreviousText",
    rootTagName: "button",
    rootProps: {
      className: cx(cssClasses.loadPrevious, isFirstPage && cssClasses.disabledLoadPrevious),
      disabled: isFirstPage,
      onClick: showPrevious
    }
  })), banner && (templateProps.templates.banner ? h(Template, _extends({}, templateProps, {
    templateKey: "banner",
    rootTagName: "fragment",
    data: {
      banner: banner,
      className: cssClasses.bannerRoot
    }
  })) : h(DefaultBanner, {
    banner: banner,
    classNames: cssClasses
  })), h("ol", {
    className: cssClasses.list
  }, hits.map(function (hit, index) {
    return h(Template, _extends({}, templateProps, {
      templateKey: "item",
      rootTagName: "li",
      rootProps: {
        className: cssClasses.item,
        onClick: function onClick(event) {
          handleInsightsClick(event);
          sendEvent('click:internal', hit, 'Hit Clicked');
        },
        onAuxClick: function onAuxClick(event) {
          handleInsightsClick(event);
          sendEvent('click:internal', hit, 'Hit Clicked');
        }
      },
      key: hit.objectID,
      data: _objectSpread(_objectSpread({}, hit), {}, {
        get __hitIndex() {
          process.env.NODE_ENV === 'development' ? warning(false, 'The `__hitIndex` property is deprecated. Use the absolute `__position` instead.') : void 0;
          return index;
        }
      }),
      bindEvent: bindEvent,
      sendEvent: sendEvent
    }));
  })), h(Template, _extends({}, templateProps, {
    templateKey: "showMoreText",
    rootTagName: "button",
    rootProps: {
      className: cx(cssClasses.loadMore, isLastPage && cssClasses.disabledLoadMore),
      disabled: isLastPage,
      onClick: showMore
    }
  })));
};
export default InfiniteHits;