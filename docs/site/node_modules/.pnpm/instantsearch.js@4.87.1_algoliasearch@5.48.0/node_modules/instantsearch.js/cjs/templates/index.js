"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
var _carousel = require("./carousel/carousel");
Object.keys(_carousel).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (key in exports && exports[key] === _carousel[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function get() {
      return _carousel[key];
    }
  });
});