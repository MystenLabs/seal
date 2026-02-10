"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _utils = require("../../lib/utils");
var _Pit = _interopRequireDefault(require("./Pit"));
var _Rheostat = _interopRequireDefault(require("./Rheostat"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _toConsumableArray(r) { return _arrayWithoutHoles(r) || _iterableToArray(r) || _unsupportedIterableToArray(r) || _nonIterableSpread(); }
function _nonIterableSpread() { throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _iterableToArray(r) { if ("undefined" != typeof Symbol && null != r[Symbol.iterator] || null != r["@@iterator"]) return Array.from(r); }
function _arrayWithoutHoles(r) { if (Array.isArray(r)) return _arrayLikeToArray(r); }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
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
var Slider = /*#__PURE__*/function (_Component) {
  _inherits(Slider, _Component);
  var _super = _createSuper(Slider);
  function Slider() {
    var _this;
    _classCallCheck(this, Slider);
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }
    _this = _super.call.apply(_super, [this].concat(args));
    _defineProperty(_assertThisInitialized(_this), "handleChange", function (_ref) {
      var values = _ref.values;
      if (!_this.isDisabled) {
        _this.props.refine(values);
      }
    });
    _defineProperty(_assertThisInitialized(_this), "createHandleComponent", function (tooltips) {
      return function (props) {
        // display only two decimals after comma,
        // and apply `tooltips.format()` if any
        var roundedValue = Math.round(
        // have to cast as a string, as the value given to the prop is a number, but becomes a string when read
        parseFloat(props['aria-valuenow']) * 100) / 100;
        var value = _typeof(tooltips) === 'object' && tooltips.format ? tooltips.format(roundedValue) : roundedValue;
        var className = (0, _instantsearchUiComponents.cx)(props.className, props['data-handle-key'] === 0 && 'rheostat-handle-lower', props['data-handle-key'] === 1 && 'rheostat-handle-upper');
        var ariaLabel = props['data-handle-key'] === 0 ? 'Minimum Filter Handle' : 'Maximum Filter Handle';
        return (0, _preact.h)("div", _extends({}, props, {
          className: className,
          "aria-label": ariaLabel
        }), tooltips && (0, _preact.h)("div", {
          className: "rheostat-tooltip"
        }, value));
      };
    });
    return _this;
  }
  _createClass(Slider, [{
    key: "isDisabled",
    get: function get() {
      return this.props.min >= this.props.max;
    }
  }, {
    key: "computeDefaultPitPoints",
    value:
    // creates an array number where to display a pit point on the slider
    function computeDefaultPitPoints(_ref2) {
      var min = _ref2.min,
        max = _ref2.max;
      var totalLength = max - min;
      var steps = 34;
      var stepsLength = totalLength / steps;
      var pitPoints = [min].concat(_toConsumableArray((0, _utils.range)({
        end: steps - 1
      }).map(function (step) {
        return min + stepsLength * (step + 1);
      })), [max]);
      return pitPoints;
    }

    // creates an array of values where the slider should snap to
  }, {
    key: "computeSnapPoints",
    value: function computeSnapPoints(_ref3) {
      var min = _ref3.min,
        max = _ref3.max,
        step = _ref3.step;
      if (!step) return undefined;
      return [].concat(_toConsumableArray((0, _utils.range)({
        start: min,
        end: max,
        step: step
      })), [max]);
    }
  }, {
    key: "render",
    value: function render() {
      var _this$props = this.props,
        tooltips = _this$props.tooltips,
        step = _this$props.step,
        pips = _this$props.pips,
        values = _this$props.values,
        cssClasses = _this$props.cssClasses;

      // @TODO: figure out why this.props needs to be non-null asserted
      var _ref4 = this.isDisabled ? {
          min: this.props.min,
          max: this.props.max + 0.001
        } : this.props,
        min = _ref4.min,
        max = _ref4.max;
      var snapPoints = this.computeSnapPoints({
        min: min,
        max: max,
        step: step
      });
      var pitPoints = pips === false ? [] : this.computeDefaultPitPoints({
        min: min,
        max: max
      });
      return (0, _preact.h)("div", {
        className: (0, _instantsearchUiComponents.cx)(cssClasses.root, this.isDisabled && cssClasses.disabledRoot)
      }, (0, _preact.h)(_Rheostat.default, {
        handle: this.createHandleComponent(tooltips),
        onChange: this.handleChange,
        min: min,
        max: max,
        pitComponent: _Pit.default,
        pitPoints: pitPoints,
        snap: true,
        snapPoints: snapPoints,
        values: this.isDisabled ? [min, max] : values,
        disabled: this.isDisabled
      }));
    }
  }]);
  return Slider;
}(_preact.Component);
var _default = exports.default = Slider;