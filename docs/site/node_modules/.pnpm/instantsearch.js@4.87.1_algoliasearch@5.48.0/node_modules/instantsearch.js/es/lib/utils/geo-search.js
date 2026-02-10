function _slicedToArray(r, e) { return _arrayWithHoles(r) || _iterableToArrayLimit(r, e) || _unsupportedIterableToArray(r, e) || _nonIterableRest(); }
function _nonIterableRest() { throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method."); }
function _unsupportedIterableToArray(r, a) { if (r) { if ("string" == typeof r) return _arrayLikeToArray(r, a); var t = {}.toString.call(r).slice(8, -1); return "Object" === t && r.constructor && (t = r.constructor.name), "Map" === t || "Set" === t ? Array.from(r) : "Arguments" === t || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t) ? _arrayLikeToArray(r, a) : void 0; } }
function _arrayLikeToArray(r, a) { (null == a || a > r.length) && (a = r.length); for (var e = 0, n = Array(a); e < a; e++) n[e] = r[e]; return n; }
function _iterableToArrayLimit(r, l) { var t = null == r ? null : "undefined" != typeof Symbol && r[Symbol.iterator] || r["@@iterator"]; if (null != t) { var e, n, i, u, a = [], f = !0, o = !1; try { if (i = (t = t.call(r)).next, 0 === l) { if (Object(t) !== t) return; f = !1; } else for (; !(f = (e = i.call(t)).done) && (a.push(e.value), a.length !== l); f = !0); } catch (r) { o = !0, n = r; } finally { try { if (!f && null != t.return && (u = t.return(), Object(u) !== u)) return; } finally { if (o) throw n; } } return a; } }
function _arrayWithHoles(r) { if (Array.isArray(r)) return r; }
var latLngRegExp = /^(-?\d+(?:\.\d+)?),\s*(-?\d+(?:\.\d+)?)$/;
export function aroundLatLngToPosition(value) {
  var pattern = value.match(latLngRegExp);

  // Since the value provided is the one send with the request, the API should
  // throw an error due to the wrong format. So throw an error should be safe.
  if (!pattern) {
    throw new Error("Invalid value for \"aroundLatLng\" parameter: \"".concat(value, "\""));
  }
  return {
    lat: parseFloat(pattern[1]),
    lng: parseFloat(pattern[2])
  };
}
function insideBoundingBoxArrayToBoundingBox(value) {
  var _value = _slicedToArray(value, 1),
    _value$ = _value[0],
    _value$2 = _value$ === void 0 ? [undefined, undefined, undefined, undefined] : _value$,
    _value$3 = _slicedToArray(_value$2, 4),
    neLat = _value$3[0],
    neLng = _value$3[1],
    swLat = _value$3[2],
    swLng = _value$3[3];

  // Since the value provided is the one send with the request, the API should
  // throw an error due to the wrong format. So throw an error should be safe.
  if (!neLat || !neLng || !swLat || !swLng) {
    throw new Error("Invalid value for \"insideBoundingBox\" parameter: [".concat(value, "]"));
  }
  return {
    northEast: {
      lat: neLat,
      lng: neLng
    },
    southWest: {
      lat: swLat,
      lng: swLng
    }
  };
}
function insideBoundingBoxStringToBoundingBox(value) {
  var _value$split$map = value.split(',').map(parseFloat),
    _value$split$map2 = _slicedToArray(_value$split$map, 4),
    neLat = _value$split$map2[0],
    neLng = _value$split$map2[1],
    swLat = _value$split$map2[2],
    swLng = _value$split$map2[3];

  // Since the value provided is the one send with the request, the API should
  // throw an error due to the wrong format. So throw an error should be safe.
  if (!neLat || !neLng || !swLat || !swLng) {
    throw new Error("Invalid value for \"insideBoundingBox\" parameter: \"".concat(value, "\""));
  }
  return {
    northEast: {
      lat: neLat,
      lng: neLng
    },
    southWest: {
      lat: swLat,
      lng: swLng
    }
  };
}
export function insideBoundingBoxToBoundingBox(value) {
  if (Array.isArray(value)) {
    return insideBoundingBoxArrayToBoundingBox(value);
  }
  return insideBoundingBoxStringToBoundingBox(value);
}