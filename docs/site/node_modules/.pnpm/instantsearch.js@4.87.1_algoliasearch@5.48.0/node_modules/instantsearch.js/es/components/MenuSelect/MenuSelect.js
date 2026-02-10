function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
import { cx } from 'instantsearch-ui-components';
import { h } from 'preact';
import { find } from "../../lib/utils/index.js";
import Template from "../Template/Template.js";
function MenuSelect(_ref) {
  var cssClasses = _ref.cssClasses,
    templateProps = _ref.templateProps,
    items = _ref.items,
    refine = _ref.refine;
  var _ref2 = find(items, function (item) {
      return item.isRefined;
    }) || {
      value: ''
    },
    selectedValue = _ref2.value;
  return h("div", {
    className: cx(cssClasses.root, items.length === 0 && cssClasses.noRefinementRoot)
  }, h("select", {
    className: cssClasses.select,
    value: selectedValue,
    onChange: function onChange(event) {
      refine(event.target.value);
    }
  }, h(Template, _extends({}, templateProps, {
    templateKey: "defaultOption",
    rootTagName: "option",
    rootProps: {
      value: '',
      className: cssClasses.option
    }
  })), items.map(function (item) {
    return h(Template, _extends({}, templateProps, {
      templateKey: "item",
      rootTagName: "option",
      rootProps: {
        value: item.value,
        className: cssClasses.option
      },
      key: item.value,
      data: item
    }));
  })));
}
export default MenuSelect;