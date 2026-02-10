function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
import { cx } from 'instantsearch-ui-components';
import { h, Fragment } from 'preact';
import Template from "../Template/Template.js";
import GeoSearchButton from "./GeoSearchButton.js";
import GeoSearchToggle from "./GeoSearchToggle.js";
var GeoSearchControls = function GeoSearchControls(_ref) {
  var cssClasses = _ref.cssClasses,
    enableRefine = _ref.enableRefine,
    enableRefineControl = _ref.enableRefineControl,
    enableClearMapRefinement = _ref.enableClearMapRefinement,
    isRefineOnMapMove = _ref.isRefineOnMapMove,
    isRefinedWithMap = _ref.isRefinedWithMap,
    hasMapMoveSinceLastRefine = _ref.hasMapMoveSinceLastRefine,
    onRefineToggle = _ref.onRefineToggle,
    onRefineClick = _ref.onRefineClick,
    onClearClick = _ref.onClearClick,
    templateProps = _ref.templateProps;
  return h(Fragment, null, enableRefine && h("div", null, enableRefineControl && h("div", {
    className: cssClasses.control
  }, isRefineOnMapMove || !hasMapMoveSinceLastRefine ? h(GeoSearchToggle, {
    classNameLabel: cx(cssClasses.label, isRefineOnMapMove && cssClasses.selectedLabel),
    classNameInput: cssClasses.input,
    checked: isRefineOnMapMove,
    onToggle: onRefineToggle
  }, h(Template, _extends({}, templateProps, {
    templateKey: "toggle",
    rootTagName: "span"
  }))) : h(GeoSearchButton, {
    className: cssClasses.redo,
    disabled: !hasMapMoveSinceLastRefine,
    onClick: onRefineClick
  }, h(Template, _extends({}, templateProps, {
    templateKey: "redo",
    rootTagName: "span"
  })))), !enableRefineControl && !isRefineOnMapMove && h("div", {
    className: cssClasses.control
  }, h(GeoSearchButton, {
    className: cx(cssClasses.redo, !hasMapMoveSinceLastRefine && cssClasses.disabledRedo),
    disabled: !hasMapMoveSinceLastRefine,
    onClick: onRefineClick
  }, h(Template, _extends({}, templateProps, {
    templateKey: "redo",
    rootTagName: "span"
  })))), enableClearMapRefinement && isRefinedWithMap && h(GeoSearchButton, {
    className: cssClasses.reset,
    onClick: onClearClick
  }, h(Template, _extends({}, templateProps, {
    templateKey: "reset",
    rootTagName: "span"
  })))));
};
export default GeoSearchControls;