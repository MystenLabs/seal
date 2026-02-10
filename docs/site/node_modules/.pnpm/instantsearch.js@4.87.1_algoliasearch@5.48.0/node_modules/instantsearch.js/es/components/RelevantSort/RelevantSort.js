import { h } from 'preact';
import Template from "../Template/Template.js";
var RelevantSort = function RelevantSort(_ref) {
  var cssClasses = _ref.cssClasses,
    templates = _ref.templates,
    isRelevantSorted = _ref.isRelevantSorted,
    isVirtualReplica = _ref.isVirtualReplica,
    refine = _ref.refine;
  return isVirtualReplica ? h("div", {
    className: cssClasses.root
  }, h(Template, {
    templateKey: "text",
    templates: templates,
    rootProps: {
      className: cssClasses.text
    },
    data: {
      isRelevantSorted: isRelevantSorted
    }
  }), h("button", {
    type: "button",
    className: cssClasses.button,
    onClick: function onClick() {
      if (isRelevantSorted) {
        refine(0);
      } else {
        refine(undefined);
      }
    }
  }, h(Template, {
    rootTagName: "span",
    templateKey: "button",
    templates: templates,
    data: {
      isRelevantSorted: isRelevantSorted
    }
  }))) : null;
};
export default RelevantSort;