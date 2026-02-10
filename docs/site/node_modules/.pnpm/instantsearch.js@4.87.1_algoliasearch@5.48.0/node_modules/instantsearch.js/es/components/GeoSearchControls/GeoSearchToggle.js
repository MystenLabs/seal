import { h } from 'preact';
var GeoSearchToggle = function GeoSearchToggle(_ref) {
  var classNameLabel = _ref.classNameLabel,
    classNameInput = _ref.classNameInput,
    checked = _ref.checked,
    onToggle = _ref.onToggle,
    children = _ref.children;
  return h("label", {
    className: classNameLabel
  }, h("input", {
    className: classNameInput,
    type: "checkbox",
    checked: checked,
    onChange: onToggle
  }), children);
};
export default GeoSearchToggle;