function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
import { cx } from 'instantsearch-ui-components';
import { h } from 'preact';
import Template from "../Template/Template.js";
var ClearRefinements = function ClearRefinements(_ref) {
  var hasRefinements = _ref.hasRefinements,
    refine = _ref.refine,
    cssClasses = _ref.cssClasses,
    templateProps = _ref.templateProps;
  return h("div", {
    className: cssClasses.root
  }, h(Template, _extends({}, templateProps, {
    templateKey: "resetLabel",
    rootTagName: "button",
    rootProps: {
      className: cx(cssClasses.button, !hasRefinements && cssClasses.disabledButton),
      onClick: refine,
      disabled: !hasRefinements
    },
    data: {
      hasRefinements: hasRefinements
    }
  })));
};
export default ClearRefinements;