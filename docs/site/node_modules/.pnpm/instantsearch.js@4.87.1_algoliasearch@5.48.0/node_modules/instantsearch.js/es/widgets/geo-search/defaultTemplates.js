import { h } from 'preact';
var _ref = h("p", null, "Your custom HTML Marker");
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
export default defaultTemplates;