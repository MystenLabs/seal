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
/* global google EventListener */
import { render } from 'preact';
var createHTMLMarker = function createHTMLMarker(googleReference) {
  var HTMLMarker = /*#__PURE__*/function (_googleReference$maps) {
    _inherits(HTMLMarker, _googleReference$maps);
    var _super = _createSuper(HTMLMarker);
    function HTMLMarker(_ref) {
      var _this;
      var __id = _ref.__id,
        position = _ref.position,
        map = _ref.map,
        template = _ref.template,
        className = _ref.className,
        _ref$anchor = _ref.anchor,
        anchor = _ref$anchor === void 0 ? {
          x: 0,
          y: 0
        } : _ref$anchor;
      _classCallCheck(this, HTMLMarker);
      _this = _super.call(this);
      _defineProperty(_assertThisInitialized(_this), "__id", void 0);
      _defineProperty(_assertThisInitialized(_this), "anchor", void 0);
      _defineProperty(_assertThisInitialized(_this), "offset", void 0);
      _defineProperty(_assertThisInitialized(_this), "listeners", void 0);
      _defineProperty(_assertThisInitialized(_this), "latLng", void 0);
      _defineProperty(_assertThisInitialized(_this), "element", void 0);
      _this.__id = __id;
      _this.anchor = anchor;
      _this.listeners = {};
      _this.latLng = new googleReference.maps.LatLng(position);
      _this.element = document.createElement('div');
      _this.element.className = className;
      _this.element.style.position = 'absolute';
      if (_typeof(template) === 'object') {
        render(template, _this.element);
      } else {
        _this.element.innerHTML = template;
      }
      _this.setMap(map);
      return _this;
    }
    _createClass(HTMLMarker, [{
      key: "onAdd",
      value: function onAdd() {
        // Append the element to the map
        this.getPanes().overlayMouseTarget.appendChild(this.element);

        // Compute the offset onAdd & cache it because afterwards
        // it won't retrieve the correct values, we also avoid
        // to read the values on every draw
        var bbBox = this.element.getBoundingClientRect();
        this.offset = {
          x: this.anchor.x + bbBox.width / 2,
          y: this.anchor.y + bbBox.height
        };

        // Force the width of the element will avoid the
        // content to collapse when we move the map
        this.element.style.width = "".concat(bbBox.width, "px");
      }
    }, {
      key: "draw",
      value: function draw() {
        var position = this.getProjection().fromLatLngToDivPixel(this.latLng);
        this.element.style.left = "".concat(Math.round(position.x - this.offset.x), "px");
        this.element.style.top = "".concat(Math.round(position.y - this.offset.y), "px");

        // Markers to the south are in front of markers to the north
        // This is the default behaviour of Google Maps
        this.element.style.zIndex = String(parseInt(this.element.style.top, 10));
      }
    }, {
      key: "onRemove",
      value: function onRemove() {
        var _this2 = this;
        if (this.element) {
          this.element.parentNode.removeChild(this.element);
          Object.keys(this.listeners).forEach(function (eventName) {
            _this2.element.removeEventListener(eventName, _this2.listeners[eventName]);
          });

          // after onRemove the class is no longer used, thus it can be deleted
          // @ts-expect-error
          delete this.element;
          // @ts-expect-error
          delete this.listeners;
        }
      }
    }, {
      key: "addListener",
      value: function addListener(eventName, listener) {
        this.listeners[eventName] = listener;
        var element = this.element;
        element.addEventListener(eventName, listener);
        return {
          remove: function remove() {
            return element.removeEventListener(eventName, listener);
          }
        };
      }
    }, {
      key: "getPosition",
      value: function getPosition() {
        return this.latLng;
      }
    }]);
    return HTMLMarker;
  }(googleReference.maps.OverlayView);
  return HTMLMarker;
};
export default createHTMLMarker;