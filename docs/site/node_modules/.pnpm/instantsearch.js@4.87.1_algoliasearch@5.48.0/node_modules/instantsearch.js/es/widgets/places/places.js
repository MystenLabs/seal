function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
var _excluded = ["placesReference", "defaultPosition"],
  _excluded2 = ["places"];
function ownKeys(e, r) { var t = Object.keys(e); if (Object.getOwnPropertySymbols) { var o = Object.getOwnPropertySymbols(e); r && (o = o.filter(function (r) { return Object.getOwnPropertyDescriptor(e, r).enumerable; })), t.push.apply(t, o); } return t; }
function _objectSpread(e) { for (var r = 1; r < arguments.length; r++) { var t = null != arguments[r] ? arguments[r] : {}; r % 2 ? ownKeys(Object(t), !0).forEach(function (r) { _defineProperty(e, r, t[r]); }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(t)) : ownKeys(Object(t)).forEach(function (r) { Object.defineProperty(e, r, Object.getOwnPropertyDescriptor(t, r)); }); } return e; }
function _defineProperty(e, r, t) { return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[r] = t, e; }
function _toPropertyKey(t) { var i = _toPrimitive(t, "string"); return "symbol" == _typeof(i) ? i : i + ""; }
function _toPrimitive(t, r) { if ("object" != _typeof(t) || !t) return t; var e = t[Symbol.toPrimitive]; if (void 0 !== e) { var i = e.call(t, r || "default"); if ("object" != _typeof(i)) return i; throw new TypeError("@@toPrimitive must return a primitive value."); } return ("string" === r ? String : Number)(t); }
function _objectWithoutProperties(e, t) { if (null == e) return {}; var o, r, i = _objectWithoutPropertiesLoose(e, t); if (Object.getOwnPropertySymbols) { var n = Object.getOwnPropertySymbols(e); for (r = 0; r < n.length; r++) o = n[r], -1 === t.indexOf(o) && {}.propertyIsEnumerable.call(e, o) && (i[o] = e[o]); } return i; }
function _objectWithoutPropertiesLoose(r, e) { if (null == r) return {}; var t = {}; for (var n in r) if ({}.hasOwnProperty.call(r, n)) { if (-1 !== e.indexOf(n)) continue; t[n] = r[n]; } return t; }
import { deprecate } from "../../lib/utils/index.js";

/* Places.js is an optional dependency, no error should be reported if the package is missing */
/** @ts-ignore */

// using the type like this requires only one ts-ignore

/**
 * This widget sets the geolocation value for the search based on the selected
 * result in the Algolia Places autocomplete.
 * @deprecated the places service is no longer offered, and this widget will be removed in InstantSearch.js v5
 */
var placesWidget = function placesWidget(widgetParams) {
  var _ref = widgetParams || {},
    placesReference = _ref.placesReference,
    _ref$defaultPosition = _ref.defaultPosition,
    defaultPosition = _ref$defaultPosition === void 0 ? [] : _ref$defaultPosition,
    placesOptions = _objectWithoutProperties(_ref, _excluded);
  if (typeof placesReference !== 'function') {
    throw new Error('The `placesReference` option requires a valid Places.js reference.');
  }
  var placesAutocomplete = placesReference(placesOptions);
  var state = {
    query: '',
    initialLatLngViaIP: undefined,
    isInitialLatLngViaIPSet: false
  };
  return {
    $$type: 'ais.places',
    $$widgetType: 'ais.places',
    init: function init(_ref2) {
      var helper = _ref2.helper;
      placesAutocomplete.on('change', function (eventOptions) {
        var _eventOptions$suggest = eventOptions.suggestion,
          value = _eventOptions$suggest.value,
          _eventOptions$suggest2 = _eventOptions$suggest.latlng,
          lat = _eventOptions$suggest2.lat,
          lng = _eventOptions$suggest2.lng;
        state.query = value;
        helper.setQueryParameter('insideBoundingBox', undefined).setQueryParameter('aroundLatLngViaIP', false).setQueryParameter('aroundLatLng', "".concat(lat, ",").concat(lng)).search();
      });
      placesAutocomplete.on('clear', function () {
        state.query = '';
        helper.setQueryParameter('insideBoundingBox', undefined);
        if (defaultPosition.length > 1) {
          helper.setQueryParameter('aroundLatLngViaIP', false).setQueryParameter('aroundLatLng', defaultPosition.join(','));
        } else {
          helper.setQueryParameter('aroundLatLngViaIP', state.initialLatLngViaIP).setQueryParameter('aroundLatLng', undefined);
        }
        helper.search();
      });
    },
    getWidgetUiState: function getWidgetUiState(uiState, _ref3) {
      var searchParameters = _ref3.searchParameters;
      var position = searchParameters.aroundLatLng || defaultPosition.join(',');
      var hasPositionSet = position !== defaultPosition.join(',');
      if (!hasPositionSet && !state.query) {
        var places = uiState.places,
          uiStateWithoutPlaces = _objectWithoutProperties(uiState, _excluded2);
        return uiStateWithoutPlaces;
      }
      return _objectSpread(_objectSpread({}, uiState), {}, {
        places: {
          query: state.query,
          position: position
        }
      });
    },
    getWidgetSearchParameters: function getWidgetSearchParameters(searchParameters, _ref4) {
      var uiState = _ref4.uiState;
      var _ref5 = uiState.places || {},
        _ref5$query = _ref5.query,
        query = _ref5$query === void 0 ? '' : _ref5$query,
        _ref5$position = _ref5.position,
        position = _ref5$position === void 0 ? defaultPosition.join(',') : _ref5$position;
      state.query = query;
      if (!state.isInitialLatLngViaIPSet) {
        state.isInitialLatLngViaIPSet = true;
        state.initialLatLngViaIP = searchParameters.aroundLatLngViaIP;
      }
      placesAutocomplete.setVal(query);
      placesAutocomplete.close();
      return searchParameters.setQueryParameter('insideBoundingBox', undefined).setQueryParameter('aroundLatLngViaIP', false).setQueryParameter('aroundLatLng', position || undefined);
    },
    getRenderState: function getRenderState(renderState, renderOptions) {
      return _objectSpread(_objectSpread({}, renderState), {}, {
        places: this.getWidgetRenderState(renderOptions)
      });
    },
    getWidgetRenderState: function getWidgetRenderState() {
      return {
        widgetParams: widgetParams
      };
    }
  };
};
export default deprecate(placesWidget, 'The places widget is deprecated and will be removed in InstantSearch.js 5.0.');