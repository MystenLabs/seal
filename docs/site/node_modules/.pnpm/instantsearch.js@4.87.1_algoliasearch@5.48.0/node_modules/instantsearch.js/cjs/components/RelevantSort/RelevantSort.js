"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;
var _preact = require("preact");
var _Template = _interopRequireDefault(require("../Template/Template"));
function _interopRequireDefault(e) { return e && e.__esModule ? e : { default: e }; }
var RelevantSort = function RelevantSort(_ref) {
  var cssClasses = _ref.cssClasses,
    templates = _ref.templates,
    isRelevantSorted = _ref.isRelevantSorted,
    isVirtualReplica = _ref.isVirtualReplica,
    refine = _ref.refine;
  return isVirtualReplica ? (0, _preact.h)("div", {
    className: cssClasses.root
  }, (0, _preact.h)(_Template.default, {
    templateKey: "text",
    templates: templates,
    rootProps: {
      className: cssClasses.text
    },
    data: {
      isRelevantSorted: isRelevantSorted
    }
  }), (0, _preact.h)("button", {
    type: "button",
    className: cssClasses.button,
    onClick: function onClick() {
      if (isRelevantSorted) {
        refine(0);
      } else {
        refine(undefined);
      }
    }
  }, (0, _preact.h)(_Template.default, {
    rootTagName: "span",
    templateKey: "button",
    templates: templates,
    data: {
      isRelevantSorted: isRelevantSorted
    }
  }))) : null;
};
var _default = exports.default = RelevantSort;