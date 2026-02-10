"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
var _algoliasearch = require("algoliasearch-helper/types/algoliasearch.js");
Object.keys(_algoliasearch).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (key in exports && exports[key] === _algoliasearch[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function get() {
      return _algoliasearch[key];
    }
  });
});