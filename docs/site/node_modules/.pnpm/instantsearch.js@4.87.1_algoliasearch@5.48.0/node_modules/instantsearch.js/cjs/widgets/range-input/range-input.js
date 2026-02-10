"use strict";

function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _RangeInput = _interopRequireDefault(require("../../components/RangeInput/RangeInput"));
var _connectRange = _interopRequireDefault(require("../../connectors/range/connectRange"));
var _suit = require("../../lib/suit");
var _templating = require("../../lib/templating");
var _utils = require("../../lib/utils");
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _slicedToArray(r, e) { return _arrayWithHoles(r) || _iterableToArrayLimit(r, e) || _unsupportedIterableToArray(r, e) || _nonIterableRest(); }
function _nonIterableRest() { throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
function _iterableToArrayLimit(r, l) { var t = null == r ? null : "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"]; if (null != t) { var e, n, i, u, a = [], f = !0, o = !1; try { if (i = (t = t.call(r)).next, 0 === l) { if (Object(t) !== t) return; f = !1; } else for (; !(f = (e = i.call(t)).done) && (a.push(e.value), a.length !== l); f = !0); } catch (r) { o = !0, n = r; } finally { try { if (!f && null != t.return && (u = t.return(), Object(u) !== u)) return; } finally { if (o) throw n; } } return a; } }
function _arrayWithHoles(r) { if (Array.isArray(r)) return r; }
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'range-input'
});
var suit = (0, _suit.component)('RangeInput');
var defaultTemplates = {
  separatorText: function separatorText() {
    return 'to';
  },
  submitText: function submitText() {
    return 'Go';
  }
};
var renderer = function renderer(_ref) {
  var containerNode = _ref.containerNode,
    cssClasses = _ref.cssClasses,
    renderState = _ref.renderState,
    templates = _ref.templates;
  return function (_ref2, isFirstRendering) {
    var refine = _ref2.refine,
      range = _ref2.range,
      start = _ref2.start,
      widgetParams = _ref2.widgetParams,
      instantSearchInstance = _ref2.instantSearchInstance;
    if (isFirstRendering) {
      renderState.templateProps = (0, _templating.prepareTemplateProps)({
        defaultTemplates: defaultTemplates,
        templatesConfig: instantSearchInstance.templatesConfig,
        templates: templates
      });
      return;
    }
    var rangeMin = range.min,
      rangeMax = range.max;
    var _start = _slicedToArray(start, 2),
      minValue = _start[0],
      maxValue = _start[1];
    var step = 1 / Math.pow(10, widgetParams.precision || 0);
    var values = {
      min: minValue !== -Infinity && minValue !== rangeMin ? minValue : undefined,
      max: maxValue !== Infinity && maxValue !== rangeMax ? maxValue : undefined
    };
    (0, _preact.render)((0, _preact.h)(_RangeInput.default, {
      min: rangeMin,
      max: rangeMax,
      step: step,
      values: values,
      cssClasses: cssClasses,
      refine: refine,
      templateProps: renderState.templateProps
    }), containerNode);
  };
};
var rangeInput = function rangeInput(widgetParams) {
  var _ref3 = widgetParams || {},
    container = _ref3.container,
    attribute = _ref3.attribute,
    min = _ref3.min,
    max = _ref3.max,
    _ref3$precision = _ref3.precision,
    precision = _ref3$precision === void 0 ? 0 : _ref3$precision,
    _ref3$cssClasses = _ref3.cssClasses,
    userCssClasses = _ref3$cssClasses === void 0 ? {} : _ref3$cssClasses,
    _ref3$templates = _ref3.templates,
    templates = _ref3$templates === void 0 ? {} : _ref3$templates;
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  var containerNode = (0, _utils.getContainerNode)(container);
  var cssClasses = {
    root: (0, _instantsearchUiComponents.cx)(suit(), userCssClasses.root),
    noRefinement: (0, _instantsearchUiComponents.cx)(suit({
      modifierName: 'noRefinement'
    })),
    form: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'form'
    }), userCssClasses.form),
    label: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'label'
    }), userCssClasses.label),
    input: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'input'
    }), userCssClasses.input),
    inputMin: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'input',
      modifierName: 'min'
    }), userCssClasses.inputMin),
    inputMax: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'input',
      modifierName: 'max'
    }), userCssClasses.inputMax),
    separator: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'separator'
    }), userCssClasses.separator),
    submit: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'submit'
    }), userCssClasses.submit)
  };
  var specializedRenderer = renderer({
    containerNode: containerNode,
    cssClasses: cssClasses,
    templates: templates,
    renderState: {}
  });
  var makeWidget = (0, _connectRange.default)(specializedRenderer, function () {
    return (0, _preact.render)(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget({
    attribute: attribute,
    min: min,
    max: max,
    precision: precision
  })), {}, {
    $$type: 'ais.rangeInput',
    $$widgetType: 'ais.rangeInput'
  });
};
var _default = exports.default = rangeInput;