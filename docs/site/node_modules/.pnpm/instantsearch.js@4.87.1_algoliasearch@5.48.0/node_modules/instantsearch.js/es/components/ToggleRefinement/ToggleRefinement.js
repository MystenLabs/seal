function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
import { h } from 'preact';
import Template from "../Template/Template.js";
var ToggleRefinement = function ToggleRefinement(_ref) {
  var currentRefinement = _ref.currentRefinement,
    refine = _ref.refine,
    cssClasses = _ref.cssClasses,
    templateProps = _ref.templateProps;
  return h("div", {
    className: cssClasses.root
  }, h("label", {
    className: cssClasses.label
  }, h("input", {
    className: cssClasses.checkbox,
    type: "checkbox",
    checked: currentRefinement.isRefined,
    onChange: function onChange(event) {
      return refine({
        isRefined: !event.target.checked
      });
    }
  }), h(Template, _extends({}, templateProps, {
    rootTagName: "span",
    rootProps: {
      className: cssClasses.labelText
    },
    templateKey: "labelText",
    data: currentRefinement
  }))));
};
export default ToggleRefinement;