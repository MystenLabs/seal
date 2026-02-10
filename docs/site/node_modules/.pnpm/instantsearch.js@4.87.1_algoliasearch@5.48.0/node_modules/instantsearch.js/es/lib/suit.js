var NAMESPACE = 'ais';
export var component = function component(componentName) {
  return function () {
    var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {},
      descendantName = _ref.descendantName,
      modifierName = _ref.modifierName;
    var descendent = descendantName ? "-".concat(descendantName) : '';
    var modifier = modifierName ? "--".concat(modifierName) : '';
    return "".concat(NAMESPACE, "-").concat(componentName).concat(descendent).concat(modifier);
  };
};