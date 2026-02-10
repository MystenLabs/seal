function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
function _slicedToArray(r, e) { return _arrayWithHoles(r) || _iterableToArrayLimit(r, e) || _unsupportedIterableToArray(r, e) || _nonIterableRest(); }
function _nonIterableRest() { throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
function _iterableToArrayLimit(r, l) { var t = null == r ? null : "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"]; if (null != t) { var e, n, i, u, a = [], f = !0, o = !1; try { if (i = (t = t.call(r)).next, 0 === l) { if (Object(t) !== t) return; f = !1; } else for (; !(f = (e = i.call(t)).done) && (a.push(e.value), a.length !== l); f = !0); } catch (r) { o = !0, n = r; } finally { try { if (!f && null != t.return && (u = t.return(), Object(u) !== u)) return; } finally { if (o) throw n; } } return a; } }
function _arrayWithHoles(r) { if (Array.isArray(r)) return r; }
import { html } from 'htm/preact';
import { createCarouselComponent, cx, generateCarouselId } from 'instantsearch-ui-components';
import { Fragment, h } from 'preact';
import { useRef, useState } from 'preact/hooks';
var Carousel = createCarouselComponent({
  createElement: h,
  Fragment: Fragment
});
function CarouselWithRefs(props) {
  var _useState = useState(false),
    _useState2 = _slicedToArray(_useState, 2),
    canScrollLeft = _useState2[0],
    setCanScrollLeft = _useState2[1];
  var _useState3 = useState(true),
    _useState4 = _slicedToArray(_useState3, 2),
    canScrollRight = _useState4[0],
    setCanScrollRight = _useState4[1];
  var carouselRefs = {
    listRef: useRef(null),
    nextButtonRef: useRef(null),
    previousButtonRef: useRef(null),
    carouselIdRef: useRef(generateCarouselId()),
    canScrollLeft: canScrollLeft,
    canScrollRight: canScrollRight,
    setCanScrollLeft: setCanScrollLeft,
    setCanScrollRight: setCanScrollRight
  };
  return h(Carousel, _extends({}, carouselRefs, props));
}
export function carousel() {
  var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {},
    cssClasses = _ref.cssClasses,
    _ref$templates = _ref.templates,
    templates = _ref$templates === void 0 ? {} : _ref$templates,
    _ref$showNavigation = _ref.showNavigation,
    showNavigation = _ref$showNavigation === void 0 ? true : _ref$showNavigation;
  return function CarouselTemplate(_ref2) {
    var items = _ref2.items,
      widgetTemplates = _ref2.templates,
      _ref2$cssClasses = _ref2.cssClasses,
      widgetCssClasses = _ref2$cssClasses === void 0 ? {} : _ref2$cssClasses,
      _ref2$sendEvent = _ref2.sendEvent,
      sendEvent = _ref2$sendEvent === void 0 ? function () {} : _ref2$sendEvent;
    var previous = templates.previous,
      next = templates.next,
      header = templates.header;
    return h(CarouselWithRefs, {
      items: items,
      sendEvent: sendEvent,
      itemComponent: widgetTemplates.item,
      headerComponent: header ? function (props) {
        return header(_objectSpread({
          html: html
        }, props));
      } : undefined,
      previousIconComponent: previous ? function () {
        return previous({
          html: html
        });
      } : undefined,
      nextIconComponent: next ? function () {
        return next({
          html: html
        });
      } : undefined,
      classNames: _objectSpread(_objectSpread({}, cssClasses), {
        list: cx(cssClasses === null || cssClasses === void 0 ? void 0 : cssClasses.list, widgetCssClasses === null || widgetCssClasses === void 0 ? void 0 : widgetCssClasses.list),
        item: cx(cssClasses === null || cssClasses === void 0 ? void 0 : cssClasses.item, widgetCssClasses === null || widgetCssClasses === void 0 ? void 0 : widgetCssClasses.item)
      }),
      showNavigation: showNavigation
    });
  };
}