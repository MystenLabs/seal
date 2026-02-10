"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.deserializePayload = deserializePayload;
exports.serializePayload = serializePayload;
function serializePayload(payload) {
  return btoa(encodeURIComponent(JSON.stringify(payload)));
}
function deserializePayload(serialized) {
  return JSON.parse(decodeURIComponent(atob(serialized)));
}