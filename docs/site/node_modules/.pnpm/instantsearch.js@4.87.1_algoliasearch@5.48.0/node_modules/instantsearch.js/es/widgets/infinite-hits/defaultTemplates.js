import { omit } from "../../lib/utils/index.js";
var defaultTemplates = {
  empty: function empty() {
    return 'No results';
  },
  showPreviousText: function showPreviousText() {
    return 'Show previous results';
  },
  showMoreText: function showMoreText() {
    return 'Show more results';
  },
  item: function item(data) {
    return JSON.stringify(omit(data, ['__hitIndex']), null, 2);
  }
};
export default defaultTemplates;