"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
var _prepareTemplateProps = require("./prepareTemplateProps");
Object.keys(_prepareTemplateProps).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (key in exports && exports[key] === _prepareTemplateProps[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function get() {
      return _prepareTemplateProps[key];
    }
  });
});
var _renderTemplate = require("./renderTemplate");
Object.keys(_renderTemplate).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (key in exports && exports[key] === _renderTemplate[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function get() {
      return _renderTemplate[key];
    }
  });
});