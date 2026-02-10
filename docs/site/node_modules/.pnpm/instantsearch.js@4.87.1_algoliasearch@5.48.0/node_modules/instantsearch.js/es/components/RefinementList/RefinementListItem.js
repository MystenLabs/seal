function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
import { h } from 'preact';
import Template from "../Template/Template.js";
function RefinementListItem(_ref) {
  var className = _ref.className,
    handleClick = _ref.handleClick,
    facetValueToRefine = _ref.facetValueToRefine,
    isRefined = _ref.isRefined,
    templateProps = _ref.templateProps,
    templateKey = _ref.templateKey,
    templateData = _ref.templateData,
    subItems = _ref.subItems;
  return h("li", {
    className: className,
    onClick: function onClick(originalEvent) {
      handleClick({
        facetValueToRefine: facetValueToRefine,
        isRefined: isRefined,
        originalEvent: originalEvent
      });
    }
  }, h(Template, _extends({}, templateProps, {
    templateKey: templateKey,
    data: templateData
  })), subItems);
}
export default RefinementListItem;