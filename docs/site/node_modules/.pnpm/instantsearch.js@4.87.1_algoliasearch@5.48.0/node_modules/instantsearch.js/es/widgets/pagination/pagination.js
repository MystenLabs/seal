function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
import { cx } from 'instantsearch-ui-components';
import { h, render } from 'preact';
import Pagination from "../../components/Pagination/Pagination.js";
import connectPagination from "../../connectors/pagination/connectPagination.js";
import { component } from "../../lib/suit.js";
import { getContainerNode, createDocumentationMessageGenerator } from "../../lib/utils/index.js";
var suit = component('Pagination');
var withUsage = createDocumentationMessageGenerator({
  name: 'pagination'
});
var defaultTemplates = {
  previous: function previous() {
    return '‹';
  },
  next: function next() {
    return '›';
  },
  page: function page(_ref) {
    var _page = _ref.page;
    return "".concat(_page);
  },
  first: function first() {
    return '«';
  },
  last: function last() {
    return '»';
  }
};
var renderer = function renderer(_ref2) {
  var containerNode = _ref2.containerNode,
    cssClasses = _ref2.cssClasses,
    templates = _ref2.templates,
    showFirst = _ref2.showFirst,
    showLast = _ref2.showLast,
    showPrevious = _ref2.showPrevious,
    showNext = _ref2.showNext,
    scrollToNode = _ref2.scrollToNode;
  return function (_ref3, isFirstRendering) {
    var createURL = _ref3.createURL,
      currentRefinement = _ref3.currentRefinement,
      nbPages = _ref3.nbPages,
      pages = _ref3.pages,
      isFirstPage = _ref3.isFirstPage,
      isLastPage = _ref3.isLastPage,
      refine = _ref3.refine;
    if (isFirstRendering) return;
    var setCurrentPage = function setCurrentPage(pageNumber) {
      refine(pageNumber);
      if (scrollToNode !== false) {
        scrollToNode.scrollIntoView();
      }
    };
    render(h(Pagination, {
      createURL: createURL,
      cssClasses: cssClasses,
      currentPage: currentRefinement,
      templates: templates,
      nbPages: nbPages,
      pages: pages,
      isFirstPage: isFirstPage,
      isLastPage: isLastPage,
      setCurrentPage: setCurrentPage,
      showFirst: showFirst,
      showLast: showLast,
      showPrevious: showPrevious,
      showNext: showNext
    }), containerNode);
  };
};
var pagination = function pagination(widgetParams) {
  var _ref4 = widgetParams || {},
    container = _ref4.container,
    _ref4$templates = _ref4.templates,
    userTemplates = _ref4$templates === void 0 ? {} : _ref4$templates,
    _ref4$cssClasses = _ref4.cssClasses,
    userCssClasses = _ref4$cssClasses === void 0 ? {} : _ref4$cssClasses,
    totalPages = _ref4.totalPages,
    padding = _ref4.padding,
    _ref4$showFirst = _ref4.showFirst,
    showFirst = _ref4$showFirst === void 0 ? true : _ref4$showFirst,
    _ref4$showLast = _ref4.showLast,
    showLast = _ref4$showLast === void 0 ? true : _ref4$showLast,
    _ref4$showPrevious = _ref4.showPrevious,
    showPrevious = _ref4$showPrevious === void 0 ? true : _ref4$showPrevious,
    _ref4$showNext = _ref4.showNext,
    showNext = _ref4$showNext === void 0 ? true : _ref4$showNext,
    _ref4$scrollTo = _ref4.scrollTo,
    userScrollTo = _ref4$scrollTo === void 0 ? 'body' : _ref4$scrollTo;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var containerNode = getContainerNode(container);
  var scrollTo = userScrollTo === true ? 'body' : userScrollTo;
  var scrollToNode = scrollTo !== false ? getContainerNode(scrollTo) : false;
  var cssClasses = {
    root: cx(suit(), userCssClasses.root),
    noRefinementRoot: cx(suit({
      modifierName: 'noRefinement'
    }), userCssClasses.noRefinementRoot),
    list: cx(suit({
      descendantName: 'list'
    }), userCssClasses.list),
    item: cx(suit({
      descendantName: 'item'
    }), userCssClasses.item),
    firstPageItem: cx(suit({
      descendantName: 'item',
      modifierName: 'firstPage'
    }), userCssClasses.firstPageItem),
    lastPageItem: cx(suit({
      descendantName: 'item',
      modifierName: 'lastPage'
    }), userCssClasses.lastPageItem),
    previousPageItem: cx(suit({
      descendantName: 'item',
      modifierName: 'previousPage'
    }), userCssClasses.previousPageItem),
    nextPageItem: cx(suit({
      descendantName: 'item',
      modifierName: 'nextPage'
    }), userCssClasses.nextPageItem),
    pageItem: cx(suit({
      descendantName: 'item',
      modifierName: 'page'
    }), userCssClasses.pageItem),
    selectedItem: cx(suit({
      descendantName: 'item',
      modifierName: 'selected'
    }), userCssClasses.selectedItem),
    disabledItem: cx(suit({
      descendantName: 'item',
      modifierName: 'disabled'
    }), userCssClasses.disabledItem),
    link: cx(suit({
      descendantName: 'link'
    }), userCssClasses.link)
  };
  var templates = _objectSpread(_objectSpread({}, defaultTemplates), userTemplates);
  var specializedRenderer = renderer({
    containerNode: containerNode,
    cssClasses: cssClasses,
    templates: templates,
    showFirst: showFirst,
    showLast: showLast,
    showPrevious: showPrevious,
    showNext: showNext,
    scrollToNode: scrollToNode
  });
  var makeWidget = connectPagination(specializedRenderer, function () {
    return render(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    totalPages: totalPages,
    padding: padding
  })), {}, {
    $$widgetType: 'ais.pagination'
  });
};
export default pagination;