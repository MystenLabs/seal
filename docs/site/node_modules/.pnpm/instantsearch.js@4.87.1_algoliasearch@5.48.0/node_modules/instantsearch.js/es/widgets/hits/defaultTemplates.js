import { omit } from "../../lib/utils/index.js";

// false positive lint error
// eslint-disable-next-line @typescript-eslint/consistent-type-imports

var defaultTemplates = {
  empty: function empty() {
    return 'No results';
  },
  item: function item(data) {
    return JSON.stringify(omit(data, ['__hitIndex']), null, 2);
  }
};
export default defaultTemplates;