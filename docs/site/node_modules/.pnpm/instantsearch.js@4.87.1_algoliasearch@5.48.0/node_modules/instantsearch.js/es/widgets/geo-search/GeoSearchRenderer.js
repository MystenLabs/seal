function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
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
import { h, render } from 'preact';
import GeoSearchControls from "../../components/GeoSearchControls/GeoSearchControls.js";
import { prepareTemplateProps } from "../../lib/templating/index.js";
var refineWithMap = function refineWithMap(_ref) {
  var refine = _ref.refine,
    mapInstance = _ref.mapInstance;
  return refine({
    northEast: mapInstance.getBounds().getNorthEast().toJSON(),
    southWest: mapInstance.getBounds().getSouthWest().toJSON()
  });
};
var collectMarkersForNextRender = function collectMarkersForNextRender(markers, nextIds) {
  return markers.reduce(function (_ref2, marker) {
    var _ref3 = _slicedToArray(_ref2, 2),
      update = _ref3[0],
      exit = _ref3[1];
    var persist = nextIds.includes(marker.__id);
    return persist ? [update.concat(marker), exit] : [update, exit.concat(marker)];
  }, [[], []]);
};
var createBoundingBoxFromMarkers = function createBoundingBoxFromMarkers(google, markers) {
  var latLngBounds = markers.reduce(function (acc, marker) {
    return acc.extend(marker.getPosition());
  }, new google.maps.LatLngBounds());
  return {
    northEast: latLngBounds.getNorthEast().toJSON(),
    southWest: latLngBounds.getSouthWest().toJSON()
  };
};
var lockUserInteraction = function lockUserInteraction(renderState, functionThatAltersTheMapPosition) {
  renderState.isUserInteraction = false;
  functionThatAltersTheMapPosition();
  renderState.isUserInteraction = true;
};
var renderer = function renderer(_ref4, isFirstRendering) {
  var items = _ref4.items,
    position = _ref4.position,
    currentRefinement = _ref4.currentRefinement,
    refine = _ref4.refine,
    clearMapRefinement = _ref4.clearMapRefinement,
    toggleRefineOnMapMove = _ref4.toggleRefineOnMapMove,
    isRefineOnMapMove = _ref4.isRefineOnMapMove,
    setMapMoveSinceLastRefine = _ref4.setMapMoveSinceLastRefine,
    hasMapMoveSinceLastRefine = _ref4.hasMapMoveSinceLastRefine,
    isRefinedWithMap = _ref4.isRefinedWithMap,
    widgetParams = _ref4.widgetParams,
    instantSearchInstance = _ref4.instantSearchInstance;
  var container = widgetParams.container,
    googleReference = widgetParams.googleReference,
    cssClasses = widgetParams.cssClasses,
    templates = widgetParams.templates,
    initialZoom = widgetParams.initialZoom,
    initialPosition = widgetParams.initialPosition,
    enableRefine = widgetParams.enableRefine,
    enableClearMapRefinement = widgetParams.enableClearMapRefinement,
    enableRefineControl = widgetParams.enableRefineControl,
    mapOptions = widgetParams.mapOptions,
    createMarker = widgetParams.createMarker,
    markerOptions = widgetParams.markerOptions,
    renderState = widgetParams.renderState;
  if (isFirstRendering) {
    renderState.isUserInteraction = true;
    renderState.isPendingRefine = false;
    renderState.markers = [];
    var rootElement = document.createElement('div');
    rootElement.className = cssClasses.root;
    container.appendChild(rootElement);
    var mapElement = document.createElement('div');
    mapElement.className = cssClasses.map;
    rootElement.appendChild(mapElement);
    var treeElement = document.createElement('div');
    treeElement.className = cssClasses.tree;
    rootElement.appendChild(treeElement);
    renderState.mapInstance = new googleReference.maps.Map(mapElement, _objectSpread({
      mapTypeControl: false,
      fullscreenControl: false,
      streetViewControl: false,
      clickableIcons: false,
      zoomControlOptions: {
        position: googleReference.maps.ControlPosition.LEFT_TOP
      }
    }, mapOptions));
    var setupListenersWhenMapIsReady = function setupListenersWhenMapIsReady() {
      var onChange = function onChange() {
        if (renderState.isUserInteraction && enableRefine) {
          setMapMoveSinceLastRefine();
          if (isRefineOnMapMove()) {
            renderState.isPendingRefine = true;
          }
        }
      };
      renderState.mapInstance.addListener('center_changed', onChange);
      renderState.mapInstance.addListener('zoom_changed', onChange);
      renderState.mapInstance.addListener('dragstart', onChange);
      renderState.mapInstance.addListener('idle', function () {
        if (renderState.isUserInteraction && renderState.isPendingRefine) {
          renderState.isPendingRefine = false;
          refineWithMap({
            mapInstance: renderState.mapInstance,
            refine: refine
          });
        }
      });
    };
    googleReference.maps.event.addListenerOnce(renderState.mapInstance, 'idle', setupListenersWhenMapIsReady);
    renderState.templateProps = prepareTemplateProps({
      templatesConfig: instantSearchInstance.templatesConfig,
      templates: templates
    });
    return;
  }

  // Collect markers that need to be updated or removed
  var nextItemsIds = items.map(function (_) {
    return _.objectID;
  });
  var _collectMarkersForNex = collectMarkersForNextRender(renderState.markers, nextItemsIds),
    _collectMarkersForNex2 = _slicedToArray(_collectMarkersForNex, 2),
    updateMarkers = _collectMarkersForNex2[0],
    exitMarkers = _collectMarkersForNex2[1];

  // Collect items that will be added
  var updateMarkerIds = updateMarkers.map(function (_) {
    return _.__id;
  });
  var nextPendingItems = items.filter(function (item) {
    return !updateMarkerIds.includes(item.objectID);
  });

  // Remove all markers that need to be removed
  exitMarkers.forEach(function (marker) {
    return marker.setMap(null);
  });

  // Create the markers from the items
  renderState.markers = updateMarkers.concat(nextPendingItems.map(function (item) {
    var marker = createMarker({
      map: renderState.mapInstance,
      item: item
    });
    Object.keys(markerOptions.events).forEach(function (eventName) {
      marker.addListener(eventName, function (event) {
        markerOptions.events[eventName]({
          map: renderState.mapInstance,
          event: event,
          item: item,
          marker: marker
        });
      });
    });
    return marker;
  }));
  var shouldUpdate = !hasMapMoveSinceLastRefine();

  // We use this value for differentiate the padding to apply during
  // fitBounds. When we don't have a currenRefinement (boundingBox)
  // we let Google Maps compute the automatic padding. But when we
  // provide the currentRefinement we explicitly set the padding
  // to `0` otherwise the map will decrease the zoom on each refine.
  var boundingBoxPadding = currentRefinement ? 0 : null;
  var boundingBox = !currentRefinement && Boolean(renderState.markers.length) ? createBoundingBoxFromMarkers(googleReference, renderState.markers) : currentRefinement;
  if (boundingBox && shouldUpdate) {
    lockUserInteraction(renderState, function () {
      renderState.mapInstance.fitBounds(new googleReference.maps.LatLngBounds(boundingBox.southWest, boundingBox.northEast), boundingBoxPadding);
    });
  } else if (shouldUpdate) {
    lockUserInteraction(renderState, function () {
      renderState.mapInstance.setCenter(position || initialPosition);
      renderState.mapInstance.setZoom(initialZoom);
    });
  }
  render(h(GeoSearchControls, {
    cssClasses: cssClasses,
    enableRefine: enableRefine,
    enableRefineControl: enableRefineControl,
    enableClearMapRefinement: enableClearMapRefinement,
    isRefineOnMapMove: isRefineOnMapMove(),
    isRefinedWithMap: isRefinedWithMap(),
    hasMapMoveSinceLastRefine: hasMapMoveSinceLastRefine(),
    onRefineToggle: toggleRefineOnMapMove,
    onRefineClick: function onRefineClick() {
      return refineWithMap({
        mapInstance: renderState.mapInstance,
        refine: refine
      });
    },
    onClearClick: clearMapRefinement,
    templateProps: renderState.templateProps
  }), container.querySelector(".".concat(cssClasses.tree)));
};
export default renderer;