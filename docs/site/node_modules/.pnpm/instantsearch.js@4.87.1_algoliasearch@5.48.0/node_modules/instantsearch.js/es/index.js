import { snippet, reverseSnippet, highlight, reverseHighlight, insights, getInsightsAnonymousUserToken } from "./helpers/index.js";
import { createInfiniteHitsSessionStorageCache } from "./lib/infiniteHitsCache/index.js";
import InstantSearch from "./lib/InstantSearch.js";
import { deprecate } from "./lib/utils/index.js";
import version from "./lib/version.js";
/**
 * InstantSearch is the main component of InstantSearch.js. This object
 * manages the widget and lets you add new ones.
 *
 * Two parameters are required to get you started with InstantSearch.js:
 *  - `indexName`: the main index that you will use for your new search UI
 *  - `searchClient`: the search client to plug to InstantSearch.js
 *
 * The [search client provided by Algolia](algolia.com/doc/api-client/getting-started/what-is-the-api-client/javascript/)
 * needs an `appId` and an `apiKey`. Those parameters can be found in your
 * [Algolia dashboard](https://www.algolia.com/api-keys).
 *
 * If you want to get up and running quickly with InstantSearch.js, have a
 * look at the [getting started](https://www.algolia.com/doc/guides/building-search-ui/getting-started/js/).
 */
var instantsearch = function instantsearch(options) {
  return new InstantSearch(options);
};
instantsearch.version = version;
instantsearch.createInfiniteHitsSessionStorageCache = deprecate(createInfiniteHitsSessionStorageCache, "import { createInfiniteHitsSessionStorageCache } from 'instantsearch.js/es/lib/infiniteHitsCache'");
instantsearch.highlight = deprecate(highlight, "import { highlight } from 'instantsearch.js/es/helpers'");
instantsearch.reverseHighlight = deprecate(reverseHighlight, "import { reverseHighlight } from 'instantsearch.js/es/helpers'");
instantsearch.snippet = deprecate(snippet, "import { snippet } from 'instantsearch.js/es/helpers'");
instantsearch.reverseSnippet = deprecate(reverseSnippet, "import { reverseSnippet } from 'instantsearch.js/es/helpers'");
instantsearch.insights = insights;
instantsearch.getInsightsAnonymousUserToken = getInsightsAnonymousUserToken;
Object.defineProperty(instantsearch, 'widgets', {
  get: function get() {
    throw new ReferenceError("\"instantsearch.widgets\" are not available from the ES build.\n\nTo import the widgets:\n\nimport { searchBox } from 'instantsearch.js/es/widgets'");
  }
});
Object.defineProperty(instantsearch, 'connectors', {
  get: function get() {
    throw new ReferenceError("\"instantsearch.connectors\" are not available from the ES build.\n\nTo import the connectors:\n\nimport { connectSearchBox } from 'instantsearch.js/es/connectors'");
  }
});
Object.defineProperty(instantsearch, 'templates', {
  get: function get() {
    throw new ReferenceError("\"instantsearch.templates\" are not available from the ES build.\n\nTo import the templates:\n\nimport { carousel } from 'instantsearch.js/es/templates'");
  }
});
export default instantsearch;
export * from "./types/index.js";
