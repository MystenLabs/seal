"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _utils = require("../../lib/utils");
var _SearchBox = _interopRequireDefault(require("../SearchBox/SearchBox"));
var _Template = _interopRequireDefault(require("../Template/Template"));
var _RefinementListItem = _interopRequireDefault(require("./RefinementListItem"));
var _excluded = ["root"];
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
function _objectWithoutProperties(e, t) { if (null == e) return {}; var o, r, i = _objectWithoutPropertiesLoose(e, t); if (Object.getOwnPropertySymbols) { var n = Object.getOwnPropertySymbols(e); for (r = 0; r < n.length; r++) o = n[r], -1 === t.indexOf(o) && {}.propertyIsEnumerable.call(e, o) && (i[o] = e[o]); } return i; }
function _objectWithoutPropertiesLoose(r, e) { if (null == r) return {}; var t = {}; for (var n in r) if ({}.hasOwnProperty.call(r, n)) { if (-1 !== e.indexOf(n)) continue; t[n] = r[n]; } return t; }
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
// CSS types

var defaultProps = {
  cssClasses: {},
  depth: 0
};
function isHierarchicalMenuItem(facetValue) {
  return facetValue.data !== undefined;
}
var RefinementList = /*#__PURE__*/function (_Component) {
  _inherits(RefinementList, _Component);
  var _super = _createSuper(RefinementList);
  function RefinementList() {
    var _this;
    _classCallCheck(this, RefinementList);
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }
    _this = _super.call.apply(_super, [this].concat(args));
    _defineProperty(_assertThisInitialized(_this), "listRef", (0, _preact.createRef)());
    _defineProperty(_assertThisInitialized(_this), "searchBox", (0, _preact.createRef)());
    _defineProperty(_assertThisInitialized(_this), "lastRefinedValue", undefined);
    _defineProperty(_assertThisInitialized(_this), "_generateFacetItem", function (facetValue) {
      var subItems;
      if (isHierarchicalMenuItem(facetValue) && Array.isArray(facetValue.data) && facetValue.data.length > 0) {
        var _this$props$cssClasse = _this.props.cssClasses,
          root = _this$props$cssClasse.root,
          cssClasses = _objectWithoutProperties(_this$props$cssClasse, _excluded);
        subItems = (0, _preact.h)(RefinementList, _extends({}, _this.props, {
          // We want to keep `root` required for external usage but not for the
          // sub items.
          cssClasses: cssClasses,
          depth: _this.props.depth + 1,
          facetValues: facetValue.data,
          showMore: false,
          className: _this.props.cssClasses.childList
        }));
      }
      var url = _this.props.createURL(facetValue.value);
      var templateData = _objectSpread(_objectSpread({}, facetValue), {}, {
        url: url,
        attribute: _this.props.attribute,
        cssClasses: _this.props.cssClasses,
        isFromSearch: _this.props.isFromSearch
      });
      var key = facetValue.value;
      if (facetValue.isRefined !== undefined) {
        key += "/".concat(facetValue.isRefined);
      }
      if (facetValue.count !== undefined) {
        key += "/".concat(facetValue.count);
      }
      var refinementListItemClassName = (0, _instantsearchUiComponents.cx)(_this.props.cssClasses.item, facetValue.isRefined && _this.props.cssClasses.selectedItem, !facetValue.count && _this.props.cssClasses.disabledItem, Boolean(isHierarchicalMenuItem(facetValue) && Array.isArray(facetValue.data) && facetValue.data.length > 0) && _this.props.cssClasses.parentItem);
      return (0, _preact.h)(_RefinementListItem.default, {
        templateKey: "item",
        key: key,
        facetValueToRefine: facetValue.value,
        handleClick: _this.handleItemClick,
        isRefined: facetValue.isRefined,
        className: refinementListItemClassName,
        subItems: subItems,
        templateData: templateData,
        templateProps: _this.props.templateProps
      });
    });
    // Click events on DOM tree like LABEL > INPUT will result in two click events
    // instead of one.
    // No matter the framework, see https://www.google.com/search?q=click+label+twice
    //
    // Thus making it hard to distinguish activation from deactivation because both click events
    // are very close. Debounce is a solution but hacky.
    //
    // So the code here checks if the click was done on or in a LABEL. If this LABEL
    // has a checkbox inside, we ignore the first click event because we will get another one.
    //
    // We also check if the click was done inside a link and then e.preventDefault() because we already
    // handle the url
    //
    // Finally, we always stop propagation of the event to avoid multiple levels RefinementLists to fail: click
    // on child would click on parent also
    _defineProperty(_assertThisInitialized(_this), "handleItemClick", function (_ref) {
      var facetValueToRefine = _ref.facetValueToRefine,
        isRefined = _ref.isRefined,
        originalEvent = _ref.originalEvent;
      if ((0, _utils.isSpecialClick)(originalEvent)) {
        // do not alter the default browser behavior
        // if one special key is down
        return;
      }
      var parent = originalEvent.target;
      if (parent === null || parent.parentNode === null) {
        return;
      }
      if (isRefined && parent.parentNode.querySelector('input[type="radio"]:checked')) {
        // Prevent refinement for being reset if the user clicks on an already checked radio button
        return;
      }
      if (parent.tagName === 'INPUT') {
        _this.refine(facetValueToRefine);
        return;
      }
      while (parent !== originalEvent.currentTarget) {
        if (parent.tagName === 'LABEL' && (parent.querySelector('input[type="checkbox"]') || parent.querySelector('input[type="radio"]'))) {
          return;
        }
        if (parent.tagName === 'A' && parent.href) {
          originalEvent.preventDefault();
        }
        parent = parent.parentNode;
      }
      originalEvent.stopPropagation();
      _this.refine(facetValueToRefine);
    });
    return _this;
  }
  _createClass(RefinementList, [{
    key: "shouldComponentUpdate",
    value: function shouldComponentUpdate(nextProps) {
      var areFacetValuesDifferent = !(0, _utils.isEqual)(this.props.facetValues, nextProps.facetValues);
      return areFacetValuesDifferent;
    }
  }, {
    key: "refine",
    value: function refine(facetValueToRefine) {
      this.lastRefinedValue = facetValueToRefine;
      this.props.toggleRefinement(facetValueToRefine);
    }
  }, {
    key: "componentWillReceiveProps",
    value: function componentWillReceiveProps(nextProps) {
      if (this.searchBox.current && !nextProps.isFromSearch) {
        this.searchBox.current.resetInput();
      }
    }

    /**
     * This sets focus on the last refined input element after a render
     * because Preact does not perform it automatically.
     * @see https://github.com/preactjs/preact/issues/3242
     */
  }, {
    key: "componentDidUpdate",
    value: function componentDidUpdate() {
      var _this$listRef$current, _this$listRef$current2, _this$lastRefinedValu;
      (_this$listRef$current = this.listRef.current) === null || _this$listRef$current === void 0 ? void 0 : (_this$listRef$current2 = _this$listRef$current.querySelector("input[value=\"".concat((_this$lastRefinedValu = this.lastRefinedValue) === null || _this$lastRefinedValu === void 0 ? void 0 : _this$lastRefinedValu.replace('"', '\\"'), "\"]"))) === null || _this$listRef$current2 === void 0 ? void 0 : _this$listRef$current2.focus();
      this.lastRefinedValue = undefined;
    }
  }, {
    key: "refineFirstValue",
    value: function refineFirstValue() {
      if (this.props.searchableSelectOnSubmit === false) {
        return;
      }
      var firstValue = this.props.facetValues && this.props.facetValues[0];
      if (firstValue) {
        var actualValue = firstValue.value;
        this.props.toggleRefinement(actualValue);
      }
    }
  }, {
    key: "render",
    value: function render() {
      var _this2 = this;
      var showMoreButtonClassName = (0, _instantsearchUiComponents.cx)(this.props.cssClasses.showMore, !(this.props.showMore === true && this.props.canToggleShowMore) && this.props.cssClasses.disabledShowMore);
      var showMoreButton = this.props.showMore === true && (0, _preact.h)(_Template.default, _extends({}, this.props.templateProps, {
        templateKey: "showMoreText",
        rootTagName: "button",
        rootProps: {
          className: showMoreButtonClassName,
          disabled: !this.props.canToggleShowMore,
          onClick: this.props.toggleShowMore
        },
        data: {
          isShowingMore: this.props.isShowingMore
        }
      }));
      var shouldDisableSearchBox = this.props.searchIsAlwaysActive !== true && !(this.props.isFromSearch || !this.props.hasExhaustiveItems);
      var searchBox = this.props.searchFacetValues && (0, _preact.h)("div", {
        className: this.props.cssClasses.searchBox
      }, (0, _preact.h)(_SearchBox.default, {
        ref: this.searchBox,
        placeholder: this.props.searchPlaceholder,
        disabled: shouldDisableSearchBox,
        cssClasses: this.props.cssClasses.searchable,
        templates: this.props.searchBoxTemplateProps.templates,
        onChange: function onChange(event) {
          return _this2.props.searchFacetValues(event.target.value);
        },
        onReset: function onReset() {
          return _this2.props.searchFacetValues('');
        },
        onSubmit: function onSubmit() {
          return _this2.refineFirstValue();
        }
        // This sets the search box to a controlled state because
        // we don't rely on the `refine` prop but on `onChange`.
        ,
        searchAsYouType: false,
        ariaLabel: "Search for filters"
      }));
      var facetValues = this.props.facetValues && this.props.facetValues.length > 0 && (0, _preact.h)("ul", {
        ref: this.listRef,
        className: this.props.cssClasses.list
      }, this.props.facetValues.map(this._generateFacetItem, this));
      var noResults = this.props.searchFacetValues && this.props.isFromSearch && (!this.props.facetValues || this.props.facetValues.length === 0) && (0, _preact.h)(_Template.default, _extends({}, this.props.templateProps, {
        templateKey: "searchableNoResults",
        rootProps: {
          className: this.props.cssClasses.noResults
        }
      }));
      var rootClassName = (0, _instantsearchUiComponents.cx)(this.props.cssClasses.root, (!this.props.facetValues || this.props.facetValues.length === 0) && this.props.cssClasses.noRefinementRoot, this.props.className);
      return (0, _preact.h)("div", {
        className: rootClassName
      }, this.props.children, searchBox, facetValues, noResults, showMoreButton);
    }
  }]);
  return RefinementList;
}(_preact.Component);
_defineProperty(RefinementList, "defaultProps", defaultProps);
var _default = exports.default = RefinementList;