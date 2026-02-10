"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getAlgoliaAgent = getAlgoliaAgent;
function getAlgoliaAgent(client) {
  var clientTyped = client;
  return clientTyped.transporter && clientTyped.transporter.userAgent ? clientTyped.transporter.userAgent.value : clientTyped._ua;
}