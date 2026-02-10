import type { SendEventForHits } from '../../lib/utils';
import type { Hit, Connector, WidgetRenderState } from '../../types';
import type { SearchResults } from 'algoliasearch-helper';
export type TransformItemsIndicesConfig = {
    indexName: string;
    indexId: string;
    hits: Hit[];
    results: SearchResults;
};
export type AutocompleteConnectorParams = {
    /**
     * Escapes HTML entities from hits string values.
     *
     * @default `true`
     */
    escapeHTML?: boolean;
    /**
     * Transforms the items of all indices.
     */
    transformItems?: (indices: TransformItemsIndicesConfig[]) => TransformItemsIndicesConfig[];
};
export type AutocompleteRenderState = {
    /**
     * The current value of the query.
     */
    currentRefinement: string;
    /**
     * The indices this widget has access to.
     */
    indices: Array<{
        /**
         * The name of the index
         */
        indexName: string;
        /**
         * The id of the index
         */
        indexId: string;
        /**
         * The resolved hits from the index matching the query.
         */
        hits: Hit[];
        /**
         * The full results object from the Algolia API.
         */
        results: SearchResults;
        /**
         * Send event to insights middleware
         */
        sendEvent: SendEventForHits;
    }>;
    /**
     * Searches into the indices with the provided query.
     */
    refine: (query: string) => void;
};
export type AutocompleteWidgetDescription = {
    $$type: 'ais.autocomplete';
    renderState: AutocompleteRenderState;
    indexRenderState: {
        autocomplete: WidgetRenderState<AutocompleteRenderState, AutocompleteConnectorParams>;
    };
    indexUiState: {
        query: string;
    };
};
export type AutocompleteConnector = Connector<AutocompleteWidgetDescription, AutocompleteConnectorParams>;
declare const connectAutocomplete: AutocompleteConnector;
export default connectAutocomplete;
