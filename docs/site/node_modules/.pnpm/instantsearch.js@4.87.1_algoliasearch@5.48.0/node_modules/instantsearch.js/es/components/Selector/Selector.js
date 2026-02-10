import { cx } from 'instantsearch-ui-components';
import { h } from 'preact';
function Selector(_ref) {
  var currentValue = _ref.currentValue,
    options = _ref.options,
    cssClasses = _ref.cssClasses,
    setValue = _ref.setValue,
    ariaLabel = _ref.ariaLabel;
  return h("select", {
    className: cx(cssClasses.select),
    onChange: function onChange(event) {
      return setValue(event.target.value);
    },
    value: "".concat(currentValue),
    "aria-label": ariaLabel
  }, options.map(function (option) {
    return h("option", {
      className: cx(cssClasses.option),
      key: option.label + option.value,
      value: "".concat(option.value)
    }, option.label);
  }));
}
export default Selector;