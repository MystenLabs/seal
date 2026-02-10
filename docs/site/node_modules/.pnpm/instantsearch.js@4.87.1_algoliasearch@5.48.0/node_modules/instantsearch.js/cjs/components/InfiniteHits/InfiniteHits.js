"use strict";

function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _listener = require("../../lib/insights/listener");
var _utils = require("../../lib/utils");
var _Template = _interopRequireDefault(require("../Template/Template"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
var DefaultBanner = function DefaultBanner(_ref) {
  var banner = _ref.banner,
    classNames = _ref.classNames;
  if (!banner.image.urls[0].url) {
    return null;
  }
  return (0, _preact.h)("aside", {
    className: (0, _instantsearchUiComponents.cx)(classNames.bannerRoot)
  }, banner.link ? (0, _preact.h)("a", {
    className: (0, _instantsearchUiComponents.cx)(classNames.bannerLink),
    href: banner.link.url,
    target: banner.link.target
  }, (0, _preact.h)("img", {
    className: (0, _instantsearchUiComponents.cx)(classNames.bannerImage),
    src: banner.image.urls[0].url,
    alt: banner.image.title
  })) : (0, _preact.h)("img", {
    className: (0, _instantsearchUiComponents.cx)(classNames.bannerImage),
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
  var handleInsightsClick = (0, _listener.createInsightsEventHandler)({
    insights: insights,
    sendEvent: sendEvent
  });
  if (results.hits.length === 0) {
    return (0, _preact.h)("div", {
      className: (0, _instantsearchUiComponents.cx)(cssClasses.root, cssClasses.emptyRoot),
      onClick: handleInsightsClick
    }, banner && (templateProps.templates.banner ? (0, _preact.h)(_Template.default, _extends({}, templateProps, {
      templateKey: "banner",
      rootTagName: "fragment",
      data: {
        banner: banner,
        className: cssClasses.bannerRoot
      }
    })) : (0, _preact.h)(DefaultBanner, {
      banner: banner,
      classNames: cssClasses
    })), (0, _preact.h)(_Template.default, _extends({}, templateProps, {
      templateKey: "empty",
      rootTagName: "fragment",
      data: results
    })));
  }
  return (0, _preact.h)("div", {
    className: cssClasses.root
  }, hasShowPrevious && (0, _preact.h)(_Template.default, _extends({}, templateProps, {
    templateKey: "showPreviousText",
    rootTagName: "button",
    rootProps: {
      className: (0, _instantsearchUiComponents.cx)(cssClasses.loadPrevious, isFirstPage && cssClasses.disabledLoadPrevious),
      disabled: isFirstPage,
      onClick: showPrevious
    }
  })), banner && (templateProps.templates.banner ? (0, _preact.h)(_Template.default, _extends({}, templateProps, {
    templateKey: "banner",
    rootTagName: "fragment",
    data: {
      banner: banner,
      className: cssClasses.bannerRoot
    }
  })) : (0, _preact.h)(DefaultBanner, {
    banner: banner,
    classNames: cssClasses
  })), (0, _preact.h)("ol", {
    className: cssClasses.list
  }, hits.map(function (hit, index) {
    return (0, _preact.h)(_Template.default, _extends({}, templateProps, {
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
          process.env.NODE_ENV === 'development' ? (0, _utils.warning)(false, 'The `__hitIndex` property is deprecated. Use the absolute `__position` instead.') : void 0;
          return index;
        }
      }),
      bindEvent: bindEvent,
      sendEvent: sendEvent
    }));
  })), (0, _preact.h)(_Template.default, _extends({}, templateProps, {
    templateKey: "showMoreText",
    rootTagName: "button",
    rootProps: {
      className: (0, _instantsearchUiComponents.cx)(cssClasses.loadMore, isLastPage && cssClasses.disabledLoadMore),
      disabled: isLastPage,
      onClick: showMore
    }
  })));
};
var _default = exports.default = InfiniteHits;