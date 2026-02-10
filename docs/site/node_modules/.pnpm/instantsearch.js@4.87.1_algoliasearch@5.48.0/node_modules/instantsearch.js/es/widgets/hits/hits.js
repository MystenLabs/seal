function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
var _excluded = ["hit", "index"];
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _objectWithoutProperties(e, t) { if (null == e) return {}; var o, r, i = _objectWithoutPropertiesLoose(e, t); if (Object.getOwnPropertySymbols) { var n = Object.getOwnPropertySymbols(e); for (r = 0; r < n.length; r++) o = n[r], -1 === t.indexOf(o) && {}.propertyIsEnumerable.call(e, o) && (i[o] = e[o]); } return i; }
function _objectWithoutPropertiesLoose(r, e) { if (null == r) return {}; var t = {}; for (var n in r) if ({}.hasOwnProperty.call(r, n)) { if (-1 !== e.indexOf(n)) continue; t[n] = r[n]; } return t; }
function _objectDestructuringEmpty(t) { if (null == t) throw new TypeError("Cannot destructure " + t); }
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
import { createHitsComponent } from 'instantsearch-ui-components';
import { Fragment, h, render } from 'preact';
import TemplateComponent from "../../components/Template/Template.js";
import connectHits from "../../connectors/hits/connectHits.js";
import { withInsights } from "../../lib/insights/index.js";
import { createInsightsEventHandler } from "../../lib/insights/listener.js";
import { prepareTemplateProps } from "../../lib/templating/index.js";
import { getContainerNode, createDocumentationMessageGenerator, warning } from "../../lib/utils/index.js";
import defaultTemplates from "./defaultTemplates.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'hits'
});
var Hits = createHitsComponent({
  createElement: h,
  Fragment: Fragment
});
var renderer = function renderer(_ref) {
  var renderState = _ref.renderState,
    cssClasses = _ref.cssClasses,
    containerNode = _ref.containerNode,
    templates = _ref.templates;
  return function (_ref2, isFirstRendering) {
    var items = _ref2.items,
      results = _ref2.results,
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
    var handleInsightsClick = createInsightsEventHandler({
      insights: insights,
      sendEvent: sendEvent
    });
    var emptyComponent = function emptyComponent(_ref3) {
      var rootProps = _extends({}, (_objectDestructuringEmpty(_ref3), _ref3));
      return h(TemplateComponent, _extends({}, renderState.templateProps, {
        rootProps: rootProps,
        templateKey: "empty",
        data: results,
        rootTagName: "fragment"
      }));
    };

    // @MAJOR: Move default hit component back to the UI library
    // once flavour specificities are erased
    var itemComponent = function itemComponent(_ref4) {
      var hit = _ref4.hit,
        index = _ref4.index,
        rootProps = _objectWithoutProperties(_ref4, _excluded);
      return h(TemplateComponent, _extends({}, renderState.templateProps, {
        templateKey: "item",
        rootTagName: "li",
        rootProps: _objectSpread(_objectSpread({}, rootProps), {}, {
          onClick: function onClick(event) {
            handleInsightsClick(event);
            rootProps.onClick();
          },
          onAuxClick: function onAuxClick(event) {
            handleInsightsClick(event);
            rootProps.onAuxClick();
          }
        }),
        data: _objectSpread(_objectSpread({}, hit), {}, {
          get __hitIndex() {
            process.env.NODE_ENV === 'development' ? warning(false, 'The `__hitIndex` property is deprecated. Use the absolute `__position` instead.') : void 0;
            return index;
          }
        }),
        bindEvent: bindEvent,
        sendEvent: sendEvent
      }));
    };
    var bannerComponent = function bannerComponent(props) {
      return h(TemplateComponent, _extends({}, renderState.templateProps, {
        templateKey: "banner",
        data: props,
        rootTagName: "fragment"
      }));
    };
    render(h(Hits, {
      hits: items,
      itemComponent: itemComponent,
      sendEvent: sendEvent,
      classNames: cssClasses,
      emptyComponent: emptyComponent,
      banner: banner,
      bannerComponent: templates.banner ? bannerComponent : undefined
    }), containerNode);
  };
};
export default (function hits(widgetParams) {
  var _ref5 = widgetParams || {},
    container = _ref5.container,
    escapeHTML = _ref5.escapeHTML,
    transformItems = _ref5.transformItems,
    _ref5$templates = _ref5.templates,
    templates = _ref5$templates === void 0 ? {} : _ref5$templates,
    _ref5$cssClasses = _ref5.cssClasses,
    cssClasses = _ref5$cssClasses === void 0 ? {} : _ref5$cssClasses;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var containerNode = getContainerNode(container);
  var specializedRenderer = renderer({
    containerNode: containerNode,
    cssClasses: cssClasses,
    renderState: {},
    templates: templates
  });
  var makeWidget = withInsights(connectHits)(specializedRenderer, function () {
    return render(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    escapeHTML: escapeHTML,
    transformItems: transformItems
  })), {}, {
    $$widgetType: 'ais.hits'
  });
});