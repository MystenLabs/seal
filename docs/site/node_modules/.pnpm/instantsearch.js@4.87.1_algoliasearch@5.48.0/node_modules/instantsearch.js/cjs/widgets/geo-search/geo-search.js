"use strict";

function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _instantsearchUiComponents = require("instantsearch-ui-components");
var _preact = require("preact");
var _connectGeoSearch = _interopRequireDefault(require("../../connectors/geo-search/connectGeoSearch"));
var _suit = require("../../lib/suit");
var _templating = require("../../lib/templating");
var _utils = require("../../lib/utils");
var _createHTMLMarker = _interopRequireDefault(require("./createHTMLMarker"));
var _defaultTemplates = _interopRequireDefault(require("./defaultTemplates"));
var _GeoSearchRenderer = _interopRequireDefault(require("./GeoSearchRenderer"));
var _excluded = ["initialZoom", "initialPosition", "templates", "cssClasses", "builtInMarker", "customHTMLMarker", "enableRefine", "enableClearMapRefinement", "enableRefineControl", "container", "googleReference"],
  _excluded2 = ["item"],
  _excluded3 = ["item"]; // global for TypeScript alone
/* global google */
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _objectWithoutProperties(e, t) { if (null == e) return {}; var o, r, i = _objectWithoutPropertiesLoose(e, t); if (Object.getOwnPropertySymbols) { var n = Object.getOwnPropertySymbols(e); for (r = 0; r < n.length; r++) o = n[r], -1 === t.indexOf(o) && {}.propertyIsEnumerable.call(e, o) && (i[o] = e[o]); } return i; }
function _objectWithoutPropertiesLoose(r, e) { if (null == r) return {}; var t = {}; for (var n in r) if ({}.hasOwnProperty.call(r, n)) { if (-1 !== e.indexOf(n)) continue; t[n] = r[n]; } return t; }
var withUsage = (0, _utils.createDocumentationMessageGenerator)({
  name: 'geo-search'
});
var suit = (0, _suit.component)('GeoSearch');
/**
 * The **GeoSearch** widget displays the list of results from the search on a Google Maps. It also provides a way to search for results based on their position. The widget also provide some of the common GeoSearch patterns like search on map interaction.
 *
 * @requirements
 *
 * Note that the GeoSearch widget uses the [geosearch](https://www.algolia.com/doc/guides/searching/geo-search) capabilities of Algolia. Your hits **must** have a `_geoloc` attribute in order to be displayed on the map.
 *
 * Currently, the feature is not compatible with multiple values in the _geoloc attribute.
 *
 * You are also responsible for loading the Google Maps library, it's not shipped with InstantSearch. You need to load the Google Maps library and pass a reference to the widget. You can find more information about how to install the library in [the Google Maps documentation](https://developers.google.com/maps/documentation/javascript/tutorial).
 *
 * Don't forget to explicitly set the `height` of the map container (default class `.ais-geo-search--map`), otherwise it won't be shown (it's a requirement of Google Maps).
 */
var geoSearch = exports.default = function geoSearch(widgetParams) {
  var _ref = widgetParams || {},
    _ref$initialZoom = _ref.initialZoom,
    initialZoom = _ref$initialZoom === void 0 ? 1 : _ref$initialZoom,
    _ref$initialPosition = _ref.initialPosition,
    initialPosition = _ref$initialPosition === void 0 ? {
      lat: 0,
      lng: 0
    } : _ref$initialPosition,
    _ref$templates = _ref.templates,
    userTemplates = _ref$templates === void 0 ? {} : _ref$templates,
    _ref$cssClasses = _ref.cssClasses,
    userCssClasses = _ref$cssClasses === void 0 ? {} : _ref$cssClasses,
    _ref$builtInMarker = _ref.builtInMarker,
    userBuiltInMarker = _ref$builtInMarker === void 0 ? {} : _ref$builtInMarker,
    userCustomHTMLMarker = _ref.customHTMLMarker,
    _ref$enableRefine = _ref.enableRefine,
    enableRefine = _ref$enableRefine === void 0 ? true : _ref$enableRefine,
    _ref$enableClearMapRe = _ref.enableClearMapRefinement,
    enableClearMapRefinement = _ref$enableClearMapRe === void 0 ? true : _ref$enableClearMapRe,
    _ref$enableRefineCont = _ref.enableRefineControl,
    enableRefineControl = _ref$enableRefineCont === void 0 ? true : _ref$enableRefineCont,
    container = _ref.container,
    googleReference = _ref.googleReference,
    otherWidgetParams = _objectWithoutProperties(_ref, _excluded);
  var defaultBuiltInMarker = {
    createOptions: function createOptions() {
      return {};
    },
    events: {}
  };
  var defaultCustomHTMLMarker = {
    createOptions: function createOptions() {
      return {};
    },
    events: {}
  };
  if (!container) {
    throw new Error(withUsage('The `container` option is required.'));
  }
  if (!googleReference) {
    throw new Error(withUsage('The `googleReference` option is required.'));
  }
  var containerNode = (0, _utils.getContainerNode)(container);
  var cssClasses = {
    root: (0, _instantsearchUiComponents.cx)(suit(), userCssClasses.root),
    // Required only to mount / unmount the Preact tree
    tree: suit({
      descendantName: 'tree'
    }),
    map: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'map'
    }), userCssClasses.map),
    control: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'control'
    }), userCssClasses.control),
    label: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'label'
    }), userCssClasses.label),
    selectedLabel: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'label',
      modifierName: 'selected'
    }), userCssClasses.selectedLabel),
    input: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'input'
    }), userCssClasses.input),
    redo: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'redo'
    }), userCssClasses.redo),
    disabledRedo: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'redo',
      modifierName: 'disabled'
    }), userCssClasses.disabledRedo),
    reset: (0, _instantsearchUiComponents.cx)(suit({
      descendantName: 'reset'
    }), userCssClasses.reset)
  };
  var templates = _objectSpread(_objectSpread({}, _defaultTemplates.default), userTemplates);
  var builtInMarker = _objectSpread(_objectSpread({}, defaultBuiltInMarker), userBuiltInMarker);
  var isCustomHTMLMarker = Boolean(userCustomHTMLMarker) || Boolean(userTemplates.HTMLMarker);
  var customHTMLMarker = isCustomHTMLMarker && _objectSpread(_objectSpread({}, defaultCustomHTMLMarker), userCustomHTMLMarker);
  var createBuiltInMarker = function createBuiltInMarker(_ref2) {
    var item = _ref2.item,
      rest = _objectWithoutProperties(_ref2, _excluded2);
    return new googleReference.maps.Marker(_objectSpread(_objectSpread(_objectSpread({}, builtInMarker.createOptions(item)), rest), {}, {
      // @ts-expect-error @types/googlemaps doesn't document this
      __id: item.objectID,
      position: item._geoloc
    }));
  };
  var HTMLMarker = (0, _createHTMLMarker.default)(googleReference);
  var createCustomHTMLMarker = function createCustomHTMLMarker(_ref3) {
    var item = _ref3.item,
      rest = _objectWithoutProperties(_ref3, _excluded3);
    return new HTMLMarker(_objectSpread(_objectSpread(_objectSpread({}, customHTMLMarker.createOptions(item)), rest), {}, {
      __id: item.objectID,
      position: item._geoloc,
      className: (0, _instantsearchUiComponents.cx)(suit({
        descendantName: 'marker'
      })),
      template: (0, _templating.renderTemplate)({
        templateKey: 'HTMLMarker',
        templates: templates,
        data: item
      })
    }));
  };
  var createMarker = !customHTMLMarker ? createBuiltInMarker : createCustomHTMLMarker;
  var markerOptions = !customHTMLMarker ? builtInMarker : customHTMLMarker;
  var makeWidget = (0, _connectGeoSearch.default)(_GeoSearchRenderer.default, function () {
    return (0, _preact.render)(null, containerNode);
  });
  return _objectSpread(_objectSpread({}, makeWidget(_objectSpread(_objectSpread({}, otherWidgetParams), {}, {
    // @TODO: this type doesn't preserve the generic correctly,
    // (but as they're internal only it's not a big problem)
    templates: templates,
    renderState: {},
    container: containerNode,
    googleReference: googleReference,
    initialZoom: initialZoom,
    initialPosition: initialPosition,
    cssClasses: cssClasses,
    createMarker: createMarker,
    markerOptions: markerOptions,
    enableRefine: enableRefine,
    enableClearMapRefinement: enableClearMapRefinement,
    enableRefineControl: enableRefineControl
  }))), {}, {
    $$widgetType: 'ais.geoSearch'
  });
};