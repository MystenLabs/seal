import { h } from 'preact';
var defaultTemplates = {
  item: function item(_ref) {
    var cssClasses = _ref.cssClasses,
      attribute = _ref.attribute,
      label = _ref.label,
      isRefined = _ref.isRefined;
    return h("label", {
      className: cssClasses.label
    }, h("input", {
      type: "radio",
      className: cssClasses.radio,
      name: attribute,
      defaultChecked: isRefined
    }), h("span", {
      className: cssClasses.labelText
    }, label));
  }
};
export default defaultTemplates;