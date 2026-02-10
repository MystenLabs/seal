import { cx } from 'instantsearch-ui-components';
import { h } from 'preact';
import { isSpecialClick } from "../../lib/utils/index.js";
import Template from "../Template/Template.js";
function Pagination(props) {
  function createClickHandler(pageNumber) {
    return function (event) {
      if (isSpecialClick(event)) {
        // do not alter the default browser behavior
        // if one special key is down
        return;
      }
      event.preventDefault();
      props.setCurrentPage(pageNumber);
    };
  }
  return h("div", {
    className: cx(props.cssClasses.root, props.nbPages <= 1 && props.cssClasses.noRefinementRoot)
  }, h("ul", {
    className: props.cssClasses.list
  }, props.showFirst && h(PaginationLink, {
    ariaLabel: "First Page",
    className: props.cssClasses.firstPageItem,
    isDisabled: props.isFirstPage,
    templates: props.templates,
    templateKey: "first",
    pageNumber: 0,
    createURL: props.createURL,
    cssClasses: props.cssClasses,
    createClickHandler: createClickHandler
  }), props.showPrevious && h(PaginationLink, {
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
    return h(PaginationLink, {
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
  }), props.showNext && h(PaginationLink, {
    ariaLabel: "Next Page",
    className: props.cssClasses.nextPageItem,
    isDisabled: props.isLastPage,
    templates: props.templates,
    templateKey: "next",
    pageNumber: props.currentPage + 1,
    createURL: props.createURL,
    cssClasses: props.cssClasses,
    createClickHandler: createClickHandler
  }), props.showLast && h(PaginationLink, {
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
  return h("li", {
    className: cx(cssClasses.item, isDisabled && cssClasses.disabledItem, className, isSelected && cssClasses.selectedItem)
  }, isDisabled ? h(Template, {
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
  }) : h(Template, {
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
export default Pagination;