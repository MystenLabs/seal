export function getObjectType(object) {
  return Object.prototype.toString.call(object).slice(8, -1);
}