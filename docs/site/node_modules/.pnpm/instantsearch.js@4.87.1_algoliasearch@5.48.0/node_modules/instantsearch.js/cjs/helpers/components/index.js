"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
var _Highlight = require("./Highlight");
Object.keys(_Highlight).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (key in exports && exports[key] === _Highlight[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function get() {
      return _Highlight[key];
    }
  });
});
var _ReverseHighlight = require("./ReverseHighlight");
Object.keys(_ReverseHighlight).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (key in exports && exports[key] === _ReverseHighlight[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function get() {
      return _ReverseHighlight[key];
    }
  });
});
var _ReverseSnippet = require("./ReverseSnippet");
Object.keys(_ReverseSnippet).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (key in exports && exports[key] === _ReverseSnippet[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function get() {
      return _ReverseSnippet[key];
    }
  });
});
var _Snippet = require("./Snippet");
Object.keys(_Snippet).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (key in exports && exports[key] === _Snippet[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function get() {
      return _Snippet[key];
    }
  });
});