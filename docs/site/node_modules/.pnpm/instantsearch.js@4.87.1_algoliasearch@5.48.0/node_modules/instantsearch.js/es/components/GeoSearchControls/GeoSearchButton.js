import { h } from 'preact';
var GeoSearchButton = function GeoSearchButton(_ref) {
  var className = _ref.className,
    _ref$disabled = _ref.disabled,
    disabled = _ref$disabled === void 0 ? false : _ref$disabled,
    onClick = _ref.onClick,
    children = _ref.children;
  return h("button", {
    className: className,
    onClick: onClick,
    disabled: disabled
  }, children);
};
export default GeoSearchButton;