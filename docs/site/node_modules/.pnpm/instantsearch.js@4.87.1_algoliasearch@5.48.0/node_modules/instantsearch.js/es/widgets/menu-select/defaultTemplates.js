import { formatNumber } from "../../lib/formatNumber.js";
var defaultTemplates = {
  item: function item(_ref) {
    var label = _ref.label,
      count = _ref.count;
    return "".concat(label, " (").concat(formatNumber(count), ")");
  },
  defaultOption: function defaultOption() {
    return 'See all';
  }
};
export default defaultTemplates;