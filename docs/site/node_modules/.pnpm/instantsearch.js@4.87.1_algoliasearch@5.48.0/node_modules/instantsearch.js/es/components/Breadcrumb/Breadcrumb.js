function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
import { cx } from 'instantsearch-ui-components';
import { h } from 'preact';
import { isSpecialClick } from "../../lib/utils/index.js";
import Template from "../Template/Template.js";
var Breadcrumb = function Breadcrumb(_ref) {
  var items = _ref.items,
    cssClasses = _ref.cssClasses,
    templateProps = _ref.templateProps,
    createURL = _ref.createURL,
    refine = _ref.refine;
  return h("div", {
    className: cx(cssClasses.root, items.length === 0 && cssClasses.noRefinementRoot)
  }, h("ul", {
    className: cssClasses.list
  }, h("li", {
    className: cx(cssClasses.item, items.length === 0 && cssClasses.selectedItem)
  }, h(Template, _extends({}, templateProps, {
    templateKey: "home",
    rootTagName: "a",
    rootProps: {
      className: cssClasses.link,
      href: createURL(null),
      onClick: function onClick(event) {
        if (isSpecialClick(event)) {
          return;
        }
        event.preventDefault();
        refine(null);
      }
    }
  }))), items.map(function (item, idx) {
    var isLast = idx === items.length - 1;
    return h("li", {
      key: item.label + idx,
      className: cx(cssClasses.item, isLast && cssClasses.selectedItem)
    }, h(Template, _extends({}, templateProps, {
      templateKey: "separator",
      rootTagName: "span",
      rootProps: {
        className: cssClasses.separator,
        'aria-hidden': true
      }
    })), isLast ? item.label : h("a", {
      className: cssClasses.link,
      href: createURL(item.value),
      onClick: function onClick(event) {
        if (isSpecialClick(event)) {
          return;
        }
        event.preventDefault();
        refine(item.value);
      }
    }, item.label));
  })));
};
export default Breadcrumb;