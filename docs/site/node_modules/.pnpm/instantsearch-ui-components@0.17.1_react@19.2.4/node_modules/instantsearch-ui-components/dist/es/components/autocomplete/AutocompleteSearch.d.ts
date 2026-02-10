import type { ComponentProps, Renderer } from '../..';
export type AutocompleteSearchProps = {
    inputProps: ComponentProps<'input'>;
    onClear: () => void;
    query: string;
    isSearchStalled: boolean;
};
export declare function createAutocompleteSearchComponent({ createElement }: Renderer): (userProps: AutocompleteSearchProps) => JSX.Element;
