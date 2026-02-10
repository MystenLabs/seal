export function isDomElement(object) {
  return object instanceof HTMLElement || Boolean(object) && object.nodeType > 0;
}