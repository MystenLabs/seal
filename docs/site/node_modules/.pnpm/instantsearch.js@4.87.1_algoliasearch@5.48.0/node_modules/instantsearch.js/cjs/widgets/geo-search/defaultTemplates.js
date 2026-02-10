"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _preact = require("preact");
var _ref = (0, _preact.h)("p", null, "Your custom HTML Marker");
var defaultTemplates = {
  HTMLMarker: function HTMLMarker() {
    return _ref;
  },
  reset: function reset() {
    return 'Clear the map refinement';
  },
  toggle: function toggle() {
    return 'Search as I move the map';
  },
  redo: function redo() {
    return 'Redo search here';
  }
};
var _default = exports.default = defaultTemplates;