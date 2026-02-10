export interface ByteStreamEmptyParameters {
}
export interface ByteStreamLengthParameters {
    length: number;
    stub?: number;
}
export interface ByteStreamViewParameters {
    view: Uint8Array;
}
export interface ByteStreamBufferParameters {
    buffer: ArrayBuffer;
}
export interface ByteStreamStringParameters {
    string: string;
}
export interface ByteStreamHexParameters {
    hexstring: string;
}
export declare type ByteStreamParameters = ByteStreamEmptyParameters | ByteStreamLengthParameters | ByteStreamViewParameters | ByteStreamBufferParameters | ByteStreamStringParameters | ByteStreamHexParameters;
export interface FindResult {
    id: number;
    position: number;
    length?: number;
}
export interface FindFirstInResult {
    /**
     * Index of the pattern in the list of the patterns
     */
    id: number;
    /**
     * Position after the pattern found
     */
    position: number;
    length: number;
}
export interface FindFirstNotInResult {
    left: FindResult;
    right: FindResult;
    value: ByteStream;
}
export interface FindPairedPatternsResult {
    left: number;
    right: number;
}
export interface FindPairedArraysResult {
    left: FindResult;
    right: FindResult;
}
export interface FindFirstSequenceResult {
    position: number;
    value: ByteStream;
}
export interface ReplacePatternResult {
    status: number;
    searchPatternPositions: number[];
    replacePatternPositions: number[];
}
export declare class ByteStream {
    private _buffer;
    private _view;
    /**
     * Constructor for ByteStream class
     * @param parameters
     */
    constructor(parameters?: ByteStreamParameters);
    /**
     * Setter for "buffer"
     * @param value
     */
    set buffer(value: ArrayBuffer);
    /**
     * Getter for "buffer"
     */
    get buffer(): ArrayBuffer;
    /**
     * Setter for "view"
     * @param value
     */
    set view(value: Uint8Array);
    /**
     * Getter for "view"
     */
    get view(): Uint8Array;
    /**
     * Getter for "length"
     */
    get length(): number;
    /**
     * Setter for "length"
     * @param value
     */
    set length(value: number);
    /**
     * Clear existing stream
     */
    clear(): void;
    /**
     * Initialize "Stream" object from existing "ArrayBuffer"
     * @param array The ArrayBuffer to copy from
     */
    fromArrayBuffer(array: ArrayBuffer): void;
    /**
     * Initialize "Stream" object from existing "Uint8Array"
     * @param  array The Uint8Array to copy from
     */
    fromUint8Array(array: Uint8Array): void;
    /**
     * Initialize "Stream" object from existing string
     * @param string The string to initialize from
     */
    fromString(string: string): void;
    /**
     * Represent "Stream" object content as a string
     * @param start Start position to convert to string
     * @param length Length of array to convert to string
     * @returns
     */
    toString(start?: number, length?: number): string;
    /**
     * Initialize "Stream" object from existing hexdecimal string
     * @param hexString String to initialize from
     */
    fromHexString(hexString: string): void;
    /**
     * Represent "Stream" object content as a hexadecimal string
     * @param start Start position to convert to string
     * @param length Length of array to convert to string
     * @returns
     */
    toHexString(start?: number, length?: number): string;
    /**
     * Return copy of existing "Stream"
     * @param start Start position of the copy
     * @param length Length of the copy
     */
    copy(start?: number, length?: number): ByteStream;
    /**
     * Return slice of existing "Stream"
     * @param start Start position of the slice
     * @param end End position of the slice
     * @returns
     */
    slice(start?: number, end?: number): ByteStream;
    /**
     * Change size of existing "Stream"
     * @param size Size for new "Stream"
     */
    realloc(size: number): void;
    /**
     * Append a new "Stream" content to the current "Stream"
     * @param stream A new "stream" to append to current "stream"
     */
    append(stream: ByteStream): void;
    /**
     * Insert "Stream" content to the current "Stream" at specific position
     * @param stream A new "stream" to insert to current "stream"
     * @param start Start position to insert to
     * @param length
     * @returns
     */
    insert(stream: ByteStream, start?: number, length?: number): boolean;
    /**
     * Check that two "Stream" objects has equal content
     * @param stream Stream to compare with
     * @returns
     */
    isEqual(stream: ByteStream): boolean;
    /**
     * Check that current "Stream" objects has equal content with input "Uint8Array"
     * @param view View to compare with
     * @returns
     */
    isEqualView(view: Uint8Array): boolean;
    /**
     * Find any byte pattern in "Stream"
     * @param pattern Stream having pattern value
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @param backward Flag to search in backward order
     * @returns
     */
    findPattern(pattern: ByteStream, start?: null | number, length?: null | number, backward?: boolean): number;
    /**
     * Find first position of any pattern from input array
     * @param patterns Array with patterns which should be found
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @param backward Flag to search in backward order
     * @returns
     */
    findFirstIn(patterns: ByteStream[], start?: null | number, length?: null | number, backward?: boolean): FindFirstInResult;
    /**
     * Find all positions of any pattern from input array
     * @param patterns Array with patterns which should be found
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @returns
     */
    findAllIn(patterns: ByteStream[], start?: null | number, length?: null | number): FindResult[];
    /**
     * Find all positions of a pattern
     * @param pattern Stream having pattern value
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @returns Array with all pattern positions or (-1) if failed
     */
    findAllPatternIn(pattern: ByteStream, start?: null | number, length?: null | number): -1 | number[];
    /**
     * Find first position of data, not included in patterns from input array
     * @param patterns Array with patterns which should be ommited
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @param backward Flag to search in backward order
     * @returns
     */
    findFirstNotIn(patterns: ByteStream[], start?: null | number, length?: null | number, backward?: boolean): FindFirstNotInResult;
    /**
     * Find all positions of data, not included in patterns from input array
     * @param patterns Array with patterns which should be omitted
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @returns
     */
    findAllNotIn(patterns: ByteStream[], start?: null | number, length?: null | number): FindFirstNotInResult[];
    /**
     * Find position of a sequence of any patterns from input array
     * @param patterns Array of pattern to look for
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @param backward Flag to search in backward order
     * @returns
     */
    findFirstSequence(patterns: ByteStream[], start?: null | number, length?: null | number, backward?: boolean): FindFirstSequenceResult;
    /**
     * Find all positions of a sequence of any patterns from input array
     * @param patterns Array of patterns to search for
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @returns
     */
    findAllSequences(patterns: ByteStream[], start?: null | number, length?: null | number): FindFirstSequenceResult[];
    /**
     * Find all paired patterns in the stream
     * @param leftPattern Left pattern to search for
     * @param rightPattern Right pattern to search for
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @returns
     */
    findPairedPatterns(leftPattern: ByteStream, rightPattern: ByteStream, start?: null | number, length?: null | number): FindPairedPatternsResult[];
    /**
     * Find all paired patterns in the stream
     * @param inputLeftPatterns Array of left patterns to search for
     * @param inputRightPatterns Array of right patterns to search for
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @returns
     */
    findPairedArrays(inputLeftPatterns: ByteStream[], inputRightPatterns: ByteStream[], start?: null | number, length?: null | number): FindPairedArraysResult[];
    /**
     * Replace one patter with other
     * @param searchPattern The pattern to search for
     * @param replacePattern The pattern to replace initial pattern
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @param findAllResult Pre-calculated results of "findAllIn"
     */
    replacePattern(searchPattern: ByteStream, replacePattern: ByteStream, start?: null | number, length?: null | number, findAllResult?: null | FindResult[]): ReplacePatternResult;
    /**
     * Skip any pattern from input array
     * @param patterns Array with patterns which should be ommited
     * @param start=null Start position to search from
     * @param length=null Length of byte block to search at
     * @param backward=false Flag to search in backward order
     * @returns
     */
    skipPatterns(patterns: ByteStream[], start?: null | number, length?: null | number, backward?: boolean): number;
    /**
     * Skip any pattern not from input array
     * @param patterns Array with patterns which should not be ommited
     * @param start
     * @param length
     * @param backward
     * @returns
     */
    skipNotPatterns(patterns: ByteStream[], start?: number | null, length?: number | null, backward?: boolean): number;
    protected prepareFindParameters(start?: null | number, length?: null | number, backward?: boolean): {
        start: number;
        length: number;
        backward: boolean;
    };
}
