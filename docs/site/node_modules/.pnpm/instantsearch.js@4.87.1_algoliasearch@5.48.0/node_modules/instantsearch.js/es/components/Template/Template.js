function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function _toConsumableArray(r) { return _arrayWithoutHoles(r) || _iterableToArray(r) || _unsupportedIterableToArray(r) || _nonIterableSpread(); }
function _nonIterableSpread() { throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _iterableToArray(r) { if ("undefined" != typeof Symbol && null != r[Symbol.iterator] || null != r["@@iterator"]) return Array.from(r); }
function _arrayWithoutHoles(r) { if (Array.isArray(r)) return _arrayLikeToArray(r); }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
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
import { h, Component, Fragment, createRef } from 'preact';
import { renderTemplate } from "../../lib/templating/index.js";
import { warning, isEqual } from "../../lib/utils/index.js";
var RawHtml = /*#__PURE__*/function (_Component) {
  _inherits(RawHtml, _Component);
  var _super = _createSuper(RawHtml);
  function RawHtml() {
    var _this;
    _classCallCheck(this, RawHtml);
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }
    _this = _super.call.apply(_super, [this].concat(args));
    _defineProperty(_assertThisInitialized(_this), "ref", createRef());
    _defineProperty(_assertThisInitialized(_this), "nodes", []);
    return _this;
  }
  _createClass(RawHtml, [{
    key: "componentDidMount",
    value: function componentDidMount() {
      var fragment = new DocumentFragment();
      var root = document.createElement('div');
      root.innerHTML = this.props.content;
      this.nodes = _toConsumableArray(root.childNodes);
      this.nodes.forEach(function (node) {
        return fragment.appendChild(node);
      });
      this.ref.current.replaceWith(fragment);
    }
  }, {
    key: "componentWillUnmount",
    value: function componentWillUnmount() {
      this.nodes.forEach(function (node) {
        if (node instanceof Element) {
          node.outerHTML = '';
          return;
        }
        node.nodeValue = '';
      });
      // if there is one TextNode first and one TextNode last, the
      // last one's nodeValue will be assigned to the first.
      if (this.nodes[0] && this.nodes[0].nodeValue) {
        this.nodes[0].nodeValue = '';
      }
    }
  }, {
    key: "render",
    value: function render() {
      return h("div", {
        ref: this.ref
      });
    }
  }]);
  return RawHtml;
}(Component);
var defaultProps = {
  data: {},
  rootTagName: 'div',
  useCustomCompileOptions: {},
  templates: {},
  templatesConfig: {}
};
// @TODO: Template should be a generic and receive TData to pass to Templates (to avoid TTemplateData to be set as `any`)
var Template = /*#__PURE__*/function (_Component2) {
  _inherits(Template, _Component2);
  var _super2 = _createSuper(Template);
  function Template() {
    _classCallCheck(this, Template);
    return _super2.apply(this, arguments);
  }
  _createClass(Template, [{
    key: "shouldComponentUpdate",
    value: function shouldComponentUpdate(nextProps) {
      return !isEqual(this.props.data, nextProps.data) || this.props.templateKey !== nextProps.templateKey || !isEqual(this.props.rootProps, nextProps.rootProps);
    }
  }, {
    key: "render",
    value: function render() {
      var _this2 = this;
      if (process.env.NODE_ENV === 'development') {
        var nonFunctionTemplates = Object.keys(this.props.templates).filter(function (key) {
          return typeof _this2.props.templates[key] !== 'function';
        });
        process.env.NODE_ENV === 'development' ? warning(nonFunctionTemplates.length === 0, "Hogan.js and string-based templates are deprecated and will not be supported in InstantSearch.js 5.x.\n\nYou can replace them with function-form templates and use either the provided `html` function or JSX templates.\n\nString-based templates: ".concat(nonFunctionTemplates.join(', '), ".\n\nSee: https://www.algolia.com/doc/guides/building-search-ui/upgrade-guides/js/#upgrade-templates")) : void 0;
      }
      var RootTagName = this.props.rootTagName === 'fragment' ? Fragment : this.props.rootTagName;
      var useCustomCompileOptions = this.props.useCustomCompileOptions[this.props.templateKey];
      var compileOptions = useCustomCompileOptions ? this.props.templatesConfig.compileOptions : {};
      var content = renderTemplate({
        templates: this.props.templates,
        templateKey: this.props.templateKey,
        compileOptions: compileOptions,
        helpers: this.props.templatesConfig.helpers,
        data: this.props.data,
        bindEvent: this.props.bindEvent,
        sendEvent: this.props.sendEvent
      });
      if (content === null) {
        // Adds a noscript to the DOM but virtual DOM is null
        // See http://facebook.github.io/react/docs/component-specs.html#render
        return null;
      }
      if (_typeof(content) === 'object') {
        return h(RootTagName, this.props.rootProps, content);
      }

      // This is to handle Hogan templates with Fragment as rootTagName
      if (RootTagName === Fragment) {
        return h(RawHtml, {
          content: content,
          key: Math.random()
        });
      }
      return h(RootTagName, _extends({}, this.props.rootProps, {
        dangerouslySetInnerHTML: {
          __html: content
        }
      }));
    }
  }]);
  return Template;
}(Component);
_defineProperty(Template, "defaultProps", defaultProps);
export default Template;