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
import { h, createRef, Component } from 'preact';
import { noop } from "../../lib/utils/index.js";
import Template from "../Template/Template.js";
var defaultProps = {
  query: '',
  showSubmit: true,
  showReset: true,
  showLoadingIndicator: true,
  autofocus: false,
  searchAsYouType: true,
  ignoreCompositionEvents: false,
  isSearchStalled: false,
  disabled: false,
  ariaLabel: 'Search',
  onChange: noop,
  onSubmit: noop,
  onReset: noop,
  refine: noop,
  inputProps: {}
};
var SearchBox = /*#__PURE__*/function (_Component) {
  _inherits(SearchBox, _Component);
  var _super = _createSuper(SearchBox);
  function SearchBox() {
    var _this;
    _classCallCheck(this, SearchBox);
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }
    _this = _super.call.apply(_super, [this].concat(args));
    _defineProperty(_assertThisInitialized(_this), "state", {
      query: _this.props.query,
      focused: false
    });
    _defineProperty(_assertThisInitialized(_this), "input", createRef());
    _defineProperty(_assertThisInitialized(_this), "onInput", function (event) {
      var _this$props$inputProp, _this$props$inputProp2;
      // @ts-expect-error the context incompatibility of `this` doesn't matter
      (_this$props$inputProp = (_this$props$inputProp2 = _this.props.inputProps).onInput) === null || _this$props$inputProp === void 0 ? void 0 : _this$props$inputProp.call(_this$props$inputProp2, event);
      var _this$props = _this.props,
        searchAsYouType = _this$props.searchAsYouType,
        refine = _this$props.refine,
        onChange = _this$props.onChange;
      var query = event.target.value;
      if (!(_this.props.ignoreCompositionEvents && event.isComposing)) {
        if (searchAsYouType) {
          refine(query);
        }
        _this.setState({
          query: query
        });
        onChange(event);
      }
    });
    _defineProperty(_assertThisInitialized(_this), "onSubmit", function (event) {
      var _this$props2 = _this.props,
        searchAsYouType = _this$props2.searchAsYouType,
        refine = _this$props2.refine,
        onSubmit = _this$props2.onSubmit;
      event.preventDefault();
      event.stopPropagation();
      if (_this.input.current) {
        _this.input.current.blur();
      }
      if (!searchAsYouType) {
        refine(_this.state.query);
      }
      onSubmit(event);
      return false;
    });
    _defineProperty(_assertThisInitialized(_this), "onReset", function (event) {
      var _this$props3 = _this.props,
        refine = _this$props3.refine,
        onReset = _this$props3.onReset;
      var query = '';
      if (_this.input.current) {
        _this.input.current.focus();
      }
      refine(query);
      _this.setState({
        query: query
      });
      onReset(event);
    });
    _defineProperty(_assertThisInitialized(_this), "onBlur", function (event) {
      var _this$props$inputProp3, _this$props$inputProp4;
      // @ts-expect-error the context incompatibility of `this` doesn't matter
      (_this$props$inputProp3 = (_this$props$inputProp4 = _this.props.inputProps).onBlur) === null || _this$props$inputProp3 === void 0 ? void 0 : _this$props$inputProp3.call(_this$props$inputProp4, event);
      _this.setState({
        focused: false
      });
    });
    _defineProperty(_assertThisInitialized(_this), "onFocus", function (event) {
      var _this$props$inputProp5, _this$props$inputProp6;
      // @ts-expect-error the context incompatibility of `this` doesn't matter
      (_this$props$inputProp5 = (_this$props$inputProp6 = _this.props.inputProps).onFocus) === null || _this$props$inputProp5 === void 0 ? void 0 : _this$props$inputProp5.call(_this$props$inputProp6, event);
      _this.setState({
        focused: true
      });
    });
    return _this;
  }
  _createClass(SearchBox, [{
    key: "resetInput",
    value:
    /**
     * This public method is used in the RefinementList SFFV search box
     * to reset the input state when an item is selected.
     *
     * @see RefinementList#componentWillReceiveProps
     * @return {undefined}
     */
    function resetInput() {
      this.setState({
        query: ''
      });
    }
  }, {
    key: "componentWillReceiveProps",
    value: function componentWillReceiveProps(nextProps) {
      /**
       * when the user is typing, we don't want to replace the query typed
       * by the user (state.query) with the query exposed by the connector (props.query)
       * see: https://github.com/algolia/instantsearch/issues/4141
       */
      if (!this.state.focused && nextProps.query !== this.state.query) {
        this.setState({
          query: nextProps.query
        });
      }
    }
  }, {
    key: "render",
    value: function render() {
      var _this$props4 = this.props,
        cssClasses = _this$props4.cssClasses,
        placeholder = _this$props4.placeholder,
        autofocus = _this$props4.autofocus,
        showSubmit = _this$props4.showSubmit,
        showReset = _this$props4.showReset,
        showLoadingIndicator = _this$props4.showLoadingIndicator,
        templates = _this$props4.templates,
        isSearchStalled = _this$props4.isSearchStalled,
        ariaLabel = _this$props4.ariaLabel,
        inputProps = _this$props4.inputProps;
      return h("div", {
        className: cssClasses.root
      }, h("form", {
        action: "",
        role: "search",
        className: cssClasses.form,
        noValidate: true,
        onSubmit: this.onSubmit,
        onReset: this.onReset
      }, h("input", _extends({}, inputProps, {
        ref: this.input,
        value: this.state.query,
        disabled: this.props.disabled,
        className: cssClasses.input,
        type: "search",
        placeholder: placeholder,
        autoFocus: autofocus,
        autoComplete: "off",
        autoCorrect: "off",
        autoCapitalize: "off"
        // @ts-expect-error `spellCheck` attribute is missing in preact JSX types
        ,
        spellCheck: "false",
        maxLength: 512,
        onInput: this.onInput
        // see: https://github.com/preactjs/preact/issues/1978
        // eslint-disable-next-line react/no-unknown-property
        ,
        oncompositionend: this.onInput,
        onBlur: this.onBlur,
        onFocus: this.onFocus,
        "aria-label": ariaLabel
      })), h(Template, {
        templateKey: "submit",
        rootTagName: "button",
        rootProps: {
          className: cssClasses.submit,
          type: 'submit',
          title: 'Submit the search query',
          hidden: !showSubmit
        },
        templates: templates,
        data: {
          cssClasses: cssClasses
        }
      }), h(Template, {
        templateKey: "reset",
        rootTagName: "button",
        rootProps: {
          className: cssClasses.reset,
          type: 'reset',
          title: 'Clear the search query',
          hidden: !(showReset && this.state.query.trim() && !isSearchStalled)
        },
        templates: templates,
        data: {
          cssClasses: cssClasses
        }
      }), showLoadingIndicator && h(Template, {
        templateKey: "loadingIndicator",
        rootTagName: "span",
        rootProps: {
          className: cssClasses.loadingIndicator,
          hidden: !isSearchStalled
        },
        templates: templates,
        data: {
          cssClasses: cssClasses
        }
      })));
    }
  }]);
  return SearchBox;
}(Component);
_defineProperty(SearchBox, "defaultProps", defaultProps);
export default SearchBox;