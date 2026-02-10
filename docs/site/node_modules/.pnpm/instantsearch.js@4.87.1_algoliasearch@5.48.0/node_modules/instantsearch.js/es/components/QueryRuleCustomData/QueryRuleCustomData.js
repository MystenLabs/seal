import { h } from 'preact';
import Template from "../Template/Template.js";
var QueryRuleCustomData = function QueryRuleCustomData(_ref) {
  var cssClasses = _ref.cssClasses,
    templates = _ref.templates,
    items = _ref.items;
  return h(Template, {
    templateKey: "default",
    templates: templates,
    rootProps: {
      className: cssClasses.root
    },
    data: {
      items: items
    }
  });
};
export default QueryRuleCustomData;