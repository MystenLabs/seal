"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _utils = require("../../lib/utils");
var _Template = _interopRequireDefault(require("../Template/Template"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function Pagination(props) {
  function createClickHandler(pageNumber) {
    return function (event) {
      if ((0, _utils.isSpecialClick)(event)) {
        // do not alter the default browser behavior
        // if one special key is down
        return;
      }
      event.preventDefault();
      props.setCurrentPage(pageNumber);
    };
  }
  return (0, _preact.h)("div", {
    className: (0, _instantsearchUiComponents.cx)(props.cssClasses.root, props.nbPages <= 1 && props.cssClasses.noRefinementRoot)
  }, (0, _preact.h)("ul", {
    className: props.cssClasses.list
  }, props.showFirst && (0, _preact.h)(PaginationLink, {
    ariaLabel: "First Page",
    className: props.cssClasses.firstPageItem,
    isDisabled: props.isFirstPage,
    templates: props.templates,
    templateKey: "first",
    pageNumber: 0,
    createURL: props.createURL,
    cssClasses: props.cssClasses,
    createClickHandler: createClickHandler
  }), props.showPrevious && (0, _preact.h)(PaginationLink, {
    ariaLabel: "Previous Page",
    className: props.cssClasses.previousPageItem,
    isDisabled: props.isFirstPage,
    templates: props.templates,
    templateKey: "previous",
    pageNumber: props.currentPage - 1,
    createURL: props.createURL,
    cssClasses: props.cssClasses,
    createClickHandler: createClickHandler
  }), props.pages.map(function (pageNumber) {
    return (0, _preact.h)(PaginationLink, {
      key: pageNumber,
      ariaLabel: "Page ".concat(pageNumber + 1),
      className: props.cssClasses.pageItem,
      isSelected: pageNumber === props.currentPage,
      templates: props.templates,
      templateKey: "page",
      pageNumber: pageNumber,
      createURL: props.createURL,
      cssClasses: props.cssClasses,
      createClickHandler: createClickHandler
    });
  }), props.showNext && (0, _preact.h)(PaginationLink, {
    ariaLabel: "Next Page",
    className: props.cssClasses.nextPageItem,
    isDisabled: props.isLastPage,
    templates: props.templates,
    templateKey: "next",
    pageNumber: props.currentPage + 1,
    createURL: props.createURL,
    cssClasses: props.cssClasses,
    createClickHandler: createClickHandler
  }), props.showLast && (0, _preact.h)(PaginationLink, {
    ariaLabel: "Last Page, Page ".concat(props.nbPages),
    className: props.cssClasses.lastPageItem,
    isDisabled: props.isLastPage,
    templates: props.templates,
    templateKey: "last",
    pageNumber: props.nbPages - 1,
    createURL: props.createURL,
    cssClasses: props.cssClasses,
    createClickHandler: createClickHandler
  })));
}
function PaginationLink(_ref) {
  var templates = _ref.templates,
    templateKey = _ref.templateKey,
    ariaLabel = _ref.ariaLabel,
    pageNumber = _ref.pageNumber,
    className = _ref.className,
    _ref$isDisabled = _ref.isDisabled,
    isDisabled = _ref$isDisabled === void 0 ? false : _ref$isDisabled,
    _ref$isSelected = _ref.isSelected,
    isSelected = _ref$isSelected === void 0 ? false : _ref$isSelected,
    cssClasses = _ref.cssClasses,
    createURL = _ref.createURL,
    createClickHandler = _ref.createClickHandler;
  return (0, _preact.h)("li", {
    className: (0, _instantsearchUiComponents.cx)(cssClasses.item, isDisabled && cssClasses.disabledItem, className, isSelected && cssClasses.selectedItem)
  }, isDisabled ? (0, _preact.h)(_Template.default, {
    rootTagName: "span",
    rootProps: {
      className: cssClasses.link,
      'aria-label': ariaLabel
    },
    templateKey: templateKey,
    templates: templates,
    data: {
      page: pageNumber + 1
    }
  }) : (0, _preact.h)(_Template.default, {
    rootTagName: "a",
    rootProps: {
      className: cssClasses.link,
      'aria-label': ariaLabel,
      href: createURL(pageNumber),
      onClick: createClickHandler(pageNumber)
    },
    templateKey: templateKey,
    templates: templates,
    data: {
      page: pageNumber + 1
    }
  }));
}
var _default = exports.default = Pagination;