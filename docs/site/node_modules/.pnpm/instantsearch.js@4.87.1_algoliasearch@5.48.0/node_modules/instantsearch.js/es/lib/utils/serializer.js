export function serializePayload(payload) {
  return btoa(encodeURIComponent(JSON.stringify(payload)));
}
export function deserializePayload(serialized) {
  return JSON.parse(decodeURIComponent(atob(serialized)));
}