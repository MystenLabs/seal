"use strict";

function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _connectDynamicWidgets = _interopRequireDefault(require("../../connectors/dynamic-widgets/connectDynamicWidgets"));
var _suit = require("../../lib/suit");
var _utils = require("../../lib/utils");
var _excluded = ["container", "widgets", "fallbackWidget"];
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _objectWithoutProperties(e, t) { if (null == e) return {}; var o, r, i = _objectWithoutPropertiesLoose(e, t); if (Object.getOwnPropertySymbols) { var n = Object.getOwnPropertySymbols(e); for (r = 0; r < n.length; r++) o = n[r], -1 === t.indexOf(o) && {}.propertyIsEnumerable.call(e, o) && (i[o] = e[o]); } return i; }
function _objectWithoutPropertiesLoose(r, e) { if (null == r) return {}; var t = {}; for (var n in r) if ({}.hasOwnProperty.call(r, n)) { if (-1 !== e.indexOf(n)) continue; t[n] = r[n]; } return t; }
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'dynamic-widgets'
});
var suit = (0, _suit.component)('DynamicWidgets');
function createContainer(rootContainer) {
  var container = document.createElement('div');
  container.className = suit({
    descendantName: 'widget'
  });
  rootContainer.appendChild(container);
  return container;
}
var dynamicWidgets = function dynamicWidgets(widgetParams) {
  var _ref = widgetParams || {},
    containerSelector = _ref.container,
    widgets = _ref.widgets,
    fallbackWidget = _ref.fallbackWidget,
    otherWidgetParams = _objectWithoutProperties(_ref, _excluded);
  if (!containerSelector) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  if (!(widgets && Array.isArray(widgets) && widgets.every(function (widget) {
    return typeof widget === 'function';
  }))) {
    throw new Error(withUsage('The `widgets` option expects an array of callbacks.'));
  }
  var userContainer = (0, _utils.getContainerNode)(containerSelector);
  var rootContainer = document.createElement('div');
  rootContainer.className = suit();
  var containers = new Map();
  var connectorWidgets = [];
  var makeWidget = (0, _connectDynamicWidgets.default)(function (_ref2, isFirstRender) {
    var attributesToRender = _ref2.attributesToRender;
    if (isFirstRender) {
      userContainer.appendChild(rootContainer);
    }
    attributesToRender.forEach(function (attribute) {
      if (!containers.has(attribute)) {
        return;
      }
      var container = containers.get(attribute);
      rootContainer.appendChild(container);
    });
  }, function () {
    userContainer.removeChild(rootContainer);
  });
  var widget = makeWidget(_objectSpread(_objectSpread({}, otherWidgetParams), {}, {
    widgets: connectorWidgets,
    fallbackWidget: typeof fallbackWidget === 'function' ? function (_ref3) {
      var attribute = _ref3.attribute;
      var container = createContainer(rootContainer);
      containers.set(attribute, container);
      return fallbackWidget({
        attribute: attribute,
        container: container
      });
    } : undefined
  }));
  return _objectSpread(_objectSpread({}, widget), {}, {
    init: function init(initOptions) {
      widgets.forEach(function (cb) {
        var container = createContainer(rootContainer);
        var childWidget = cb(container);
        var attribute = (0, _utils.getWidgetAttribute)(childWidget, initOptions);
        containers.set(attribute, container);
        connectorWidgets.push(childWidget);
      });
      widget.init(initOptions);
    },
    $$widgetType: 'ais.dynamicWidgets'
  });
};
var _default = exports.default = dynamicWidgets;