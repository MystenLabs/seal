"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _Template = _interopRequireDefault(require("../Template/Template"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
function _classCallCheck(a, n) { if (!(a instanceof n)) throw new TypeError("Cannot call a class as a function"); }
function _defineProperties(e, r) { for (var t = 0; t < r.length; t++) { var o = r[t]; o.enumerable = o.enumerable || !1, o.configurable = !0, "value" in o && (o.writable = !0), Object.defineProperty(e, _toPropertyKey(o.key), o); } }
function _createClass(e, r, t) { return r && _defineProperties(e.prototype, r), t && _defineProperties(e, t), Object.defineProperty(e, "prototype", { writable: !1 }), e; }
function _inherits(t, e) { if ("function" != typeof e && null !== e) throw new TypeError("Super expression must either be null or a function"); t.prototype = Object.create(e && e.prototype, { constructor: { value: t, writable: !0, configurable: !0 } }), Object.defineProperty(t, "prototype", { writable: !1 }), e && _setPrototypeOf(t, e); }
function _setPrototypeOf(t, e) { return _setPrototypeOf = Object.setPrototypeOf ? Object.setPrototypeOf.bind() : function (t, e) { return t.__proto__ = e, t; }, _setPrototypeOf(t, e); }
function _createSuper(t) { var r = _isNativeReflectConstruct(); return function () { var e, o = _getPrototypeOf(t); if (r) { var s = _getPrototypeOf(this).constructor; e = Reflect.construct(o, arguments, s); } else e = o.apply(this, arguments); return _possibleConstructorReturn(this, e); }; }
function _possibleConstructorReturn(t, e) { if (e && ("object" == _typeof(e) || "function" == typeof e)) return e; if (void 0 !== e) throw new TypeError("Derived constructors may only return object or undefined"); return _assertThisInitialized(t); }
function _assertThisInitialized(e) { if (void 0 === e) throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); return e; }
function _isNativeReflectConstruct() { try { var t = !Boolean.prototype.valueOf.call(Reflect.construct(Boolean, [], function () {})); } catch (t) {} return (_isNativeReflectConstruct = function _isNativeReflectConstruct() { return !!t; })(); }
function _getPrototypeOf(t) { return _getPrototypeOf = Object.setPrototypeOf ? Object.getPrototypeOf.bind() : function (t) { return t.__proto__ || Object.getPrototypeOf(t); }, _getPrototypeOf(t); }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
// Strips leading `0` from a positive number value
function stripLeadingZeroFromInput(value) {
  return value.replace(/^(0+)\d/, function (part) {
    return Number(part).toString();
  });
}
var RangeInput = /*#__PURE__*/function (_Component) {
  _inherits(RangeInput, _Component);
  var _super = _createSuper(RangeInput);
  function RangeInput() {
    var _this$props$values$mi, _this$props$values$ma;
    var _this;
    _classCallCheck(this, RangeInput);
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }
    _this = _super.call.apply(_super, [this].concat(args));
    _defineProperty(_assertThisInitialized(_this), "state", {
      min: (_this$props$values$mi = _this.props.values.min) === null || _this$props$values$mi === void 0 ? void 0 : _this$props$values$mi.toString(),
      max: (_this$props$values$ma = _this.props.values.max) === null || _this$props$values$ma === void 0 ? void 0 : _this$props$values$ma.toString()
    });
    _defineProperty(_assertThisInitialized(_this), "onInput", function (key) {
      return function (event) {
        var _ref = event.currentTarget,
          value = _ref.value;
        _this.setState(_defineProperty({}, key, value));
      };
    });
    _defineProperty(_assertThisInitialized(_this), "onSubmit", function (event) {
      event.preventDefault();
      var _this$state = _this.state,
        min = _this$state.min,
        max = _this$state.max;
      _this.props.refine([min ? Number(min) : undefined, max ? Number(max) : undefined]);
    });
    return _this;
  }
  _createClass(RangeInput, [{
    key: "componentWillReceiveProps",
    value: function componentWillReceiveProps(nextProps) {
      var _nextProps$values$min, _nextProps$values$max;
      this.setState({
        min: (_nextProps$values$min = nextProps.values.min) === null || _nextProps$values$min === void 0 ? void 0 : _nextProps$values$min.toString(),
        max: (_nextProps$values$max = nextProps.values.max) === null || _nextProps$values$max === void 0 ? void 0 : _nextProps$values$max.toString()
      });
    }
  }, {
    key: "render",
    value: function render() {
      var _this$state2 = this.state,
        minValue = _this$state2.min,
        maxValue = _this$state2.max;
      var _this$props = this.props,
        min = _this$props.min,
        max = _this$props.max,
        step = _this$props.step,
        cssClasses = _this$props.cssClasses,
        templateProps = _this$props.templateProps;
      var isDisabled = min && max ? min >= max : false;
      var hasRefinements = Boolean(minValue || maxValue);
      var rootClassNames = (0, _instantsearchUiComponents.cx)(cssClasses.root, !hasRefinements && cssClasses.noRefinement);
      return (0, _preact.h)("div", {
        className: rootClassNames
      }, (0, _preact.h)("form", {
        className: cssClasses.form,
        onSubmit: this.onSubmit
      }, (0, _preact.h)("label", {
        className: cssClasses.label
      }, (0, _preact.h)("input", {
        className: (0, _instantsearchUiComponents.cx)(cssClasses.input, cssClasses.inputMin),
        type: "number",
        min: min,
        max: max,
        step: step,
        value: stripLeadingZeroFromInput(minValue !== null && minValue !== void 0 ? minValue : ''),
        onInput: this.onInput('min'),
        placeholder: min === null || min === void 0 ? void 0 : min.toString(),
        disabled: isDisabled
      })), (0, _preact.h)(_Template.default, _extends({}, templateProps, {
        templateKey: "separatorText",
        rootTagName: "span",
        rootProps: {
          className: cssClasses.separator
        }
      })), (0, _preact.h)("label", {
        className: cssClasses.label
      }, (0, _preact.h)("input", {
        className: (0, _instantsearchUiComponents.cx)(cssClasses.input, cssClasses.inputMax),
        type: "number",
        min: min,
        max: max,
        step: step,
        value: stripLeadingZeroFromInput(maxValue !== null && maxValue !== void 0 ? maxValue : ''),
        onInput: this.onInput('max'),
        placeholder: max === null || max === void 0 ? void 0 : max.toString(),
        disabled: isDisabled
      })), (0, _preact.h)(_Template.default, _extends({}, templateProps, {
        templateKey: "submitText",
        rootTagName: "button",
        rootProps: {
          type: 'submit',
          className: cssClasses.submit,
          disabled: isDisabled
        }
      }))));
    }
  }]);
  return RangeInput;
}(_preact.Component);
var _default = exports.default = RangeInput;