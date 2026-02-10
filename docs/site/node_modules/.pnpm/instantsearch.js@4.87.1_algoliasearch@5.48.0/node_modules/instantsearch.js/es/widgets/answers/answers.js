function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
import { cx } from 'instantsearch-ui-components';
import { h, render } from 'preact';
import Answers from "../../components/Answers/Answers.js";
import connectAnswers from "../../connectors/answers/connectAnswers.js";
import { component } from "../../lib/suit.js";
import { prepareTemplateProps } from "../../lib/templating/index.js";
import { createDocumentationMessageGenerator, deprecate, getContainerNode } from "../../lib/utils/index.js";
import defaultTemplates from "./defaultTemplates.js";
var withUsage = createDocumentationMessageGenerator({
  name: 'answers'
});
var suit = component('Answers');
var renderer = function renderer(_ref) {
  var containerNode = _ref.containerNode,
    cssClasses = _ref.cssClasses,
    renderState = _ref.renderState,
    templates = _ref.templates;
  return function (_ref2, isFirstRendering) {
    var hits = _ref2.hits,
      isLoading = _ref2.isLoading,
      instantSearchInstance = _ref2.instantSearchInstance;
    if (isFirstRendering) {
      renderState.templateProps = prepareTemplateProps({
        defaultTemplates: defaultTemplates,
        templatesConfig: instantSearchInstance.templatesConfig,
        templates: templates
      });
      return;
    }
    render(h(Answers, {
      cssClasses: cssClasses,
      hits: hits,
      isLoading: isLoading,
      templateProps: renderState.templateProps
    }), containerNode);
  };
};
/**
 * @deprecated the answers service is no longer offered, and this widget will be removed in InstantSearch.js v5
 */
var answersWidget = function answersWidget(widgetParams) {
  var _ref3 = widgetParams || {},
    container = _ref3.container,
    attributesForPrediction = _ref3.attributesForPrediction,
    queryLanguages = _ref3.queryLanguages,
    nbHits = _ref3.nbHits,
    searchDebounceTime = _ref3.searchDebounceTime,
    renderDebounceTime = _ref3.renderDebounceTime,
    escapeHTML = _ref3.escapeHTML,
    extraParameters = _ref3.extraParameters,
    _ref3$templates = _ref3.templates,
    templates = _ref3$templates === void 0 ? {} : _ref3$templates,
    _ref3$cssClasses = _ref3.cssClasses,
    userCssClasses = _ref3$cssClasses === void 0 ? {} : _ref3$cssClasses;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var containerNode = getContainerNode(container);
  var cssClasses = {
    root: cx(suit(), userCssClasses.root),
    emptyRoot: cx(suit({
      modifierName: 'empty'
    }), userCssClasses.emptyRoot),
    header: cx(suit({
      descendantName: 'header'
    }), userCssClasses.header),
    loader: cx(suit({
      descendantName: 'loader'
    }), userCssClasses.loader),
    list: cx(suit({
      descendantName: 'list'
    }), userCssClasses.list),
    item: cx(suit({
      descendantName: 'item'
    }), userCssClasses.item)
  };
  var specializedRenderer = renderer({
    containerNode: containerNode,
    cssClasses: cssClasses,
    templates: templates,
    renderState: {}
  });
  var makeWidget = connectAnswers(specializedRenderer, function () {
    return render(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    attributesForPrediction: attributesForPrediction,
    queryLanguages: queryLanguages,
    nbHits: nbHits,
    searchDebounceTime: searchDebounceTime,
    renderDebounceTime: renderDebounceTime,
    escapeHTML: escapeHTML,
    extraParameters: extraParameters
  })), {}, {
    $$widgetType: 'ais.answers'
  });
};
export default deprecate(answersWidget, 'The answers widget is deprecated and will be removed in InstantSearch.js 5.0');