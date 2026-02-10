import { ByteStream, FindFirstNotInResult, FindFirstSequenceResult, FindPairedArraysResult, FindPairedPatternsResult } from "./byte_stream";
export interface SeqStreamBaseParameters {
    backward?: boolean;
    start?: number;
    appendBlock?: number;
}
export interface SeqStreamLengthParameters extends SeqStreamBaseParameters {
    length: number;
}
export interface SeqStreamStreamParameters extends SeqStreamBaseParameters {
    stream: ByteStream;
}
export interface SeqStreamViewParameters extends SeqStreamBaseParameters {
    view: Uint8Array;
}
export interface SeqStreamBufferParameters extends SeqStreamBaseParameters {
    buffer: ArrayBuffer;
}
export interface SeqStreamStringParameters {
    string: string;
}
export interface SeqStreamHexParameters {
    hexstring: string;
}
export declare type SeqStreamParameters = SeqStreamBaseParameters | SeqStreamLengthParameters | SeqStreamBufferParameters | SeqStreamStreamParameters | SeqStreamViewParameters | SeqStreamStringParameters | SeqStreamHexParameters;
export declare class SeqStream {
    static APPEND_BLOCK: number;
    /**
     * Major stream
     */
    private _stream;
    /**
     * Length of the major stream
     */
    private _length;
    /**
     * Start position to search
     */
    private _start;
    /**
     * Flag to search in backward direction
     */
    backward: boolean;
    /**
     * Length of a block when append information to major stream
     */
    appendBlock: number;
    prevLength: number;
    prevStart: number;
    /**
     * Constructor for "SeqStream" class
     * @param parameters
     */
    constructor(parameters?: SeqStreamParameters);
    /**
     * Setter for "stream" property
     */
    set stream(value: ByteStream);
    /**
     * Getter for "stream" property
     */
    get stream(): ByteStream;
    /**
     * Setter for "length" property
     * @param value
     */
    set length(value: number);
    /**
     * Getter for "length" property
     * @returns
     */
    get length(): number;
    /**
     * Setter for "start" property
     * @param value
     */
    set start(value: number);
    /**
     * Getter for "start" property
     * @returns
     */
    get start(): number;
    /**
     * Return ArrayBuffer with having value of existing SeqStream length
     * @return
     */
    get buffer(): ArrayBuffer;
    /**
     * Reset current position of the "SeqStream"
     */
    resetPosition(): void;
    /**
     * Find any byte pattern in "ByteStream"
     * @param pattern Stream having pattern value
     * @param ga Maximum gap between start position and position of nearest object
     * @returns
     */
    findPattern(pattern: ByteStream, gap?: null | number): number;
    /**
     * Find first position of any pattern from input array
     * @param patterns Array with patterns which should be found
     * @param gap Maximum gap between start position and position of nearest object
     * @returns
     */
    findFirstIn(patterns: ByteStream[], gap?: null | number): import("./byte_stream").FindFirstInResult | {
        id: number;
        position: number;
    };
    /**
     * Find all positions of any pattern from input array
     * @param patterns Array with patterns which should be found
     * @returns
     */
    findAllIn(patterns: ByteStream[]): import("./byte_stream").FindResult[];
    /**
     * Find first position of data, not included in patterns from input array
     * @param patterns Array with patterns which should be omitted
     * @param gap Maximum gap between start position and position of nearest object
     * @returns
     */
    findFirstNotIn(patterns: ByteStream[], gap?: null | number): FindFirstNotInResult;
    /**
     * Find all positions of data, not included in patterns from input array
     * @param patterns Array with patterns which should be omitted
     * @returns
     */
    findAllNotIn(patterns: ByteStream[]): FindFirstNotInResult[];
    /**
     * Find position of a sequence of any patterns from input array
     * @param patterns Array with patterns which should be omitted
     * @param length Length to search sequence for
     * @param gap Maximum gap between start position and position of nearest object
     * @returns
     */
    findFirstSequence(patterns: ByteStream[], length?: null | number, gap?: null | number): FindFirstSequenceResult;
    /**
     * Find position of a sequence of any patterns from input array
     * @param patterns Array with patterns which should be found
     * @returns
     */
    findAllSequences(patterns: ByteStream[]): FindFirstSequenceResult[];
    /**
     * Find all paired patterns in the stream
     * @param leftPattern Left pattern to search for
     * @param rightPattern Right pattern to search for
     * @param gap Maximum gap between start position and position of nearest object
     * @returns
     */
    findPairedPatterns(leftPattern: ByteStream, rightPattern: ByteStream, gap?: null | number): FindPairedPatternsResult[];
    /**
     * Find all paired patterns in the stream
     * @param leftPatterns Array of left patterns to search for
     * @param rightPatterns Array of right patterns to search for
     * @param gap Maximum gap between start position and position of nearest object
     * @returns
     */
    findPairedArrays(leftPatterns: ByteStream[], rightPatterns: ByteStream[], gap?: null | number): FindPairedArraysResult[];
    /**
     * Replace one patter with other
     * @param searchPattern The pattern to search for
     * @param replacePattern The pattern to replace initial pattern
     * @returns
     */
    replacePattern(searchPattern: ByteStream, replacePattern: ByteStream): import("./byte_stream").ReplacePatternResult;
    /**
     * Skip of any pattern from input array
     * @param patterns Array with patterns which should be omitted
     * @returns
     */
    skipPatterns(patterns: ByteStream[]): number;
    /**
     * Skip of any pattern from input array
     * @param patterns Array with patterns which should be omitted
     * @returns
     */
    skipNotPatterns(patterns: ByteStream[]): number;
    /**
     * Append a new "Stream" content to the current "Stream"
     * @param stream A new "stream" to append to current "stream"
     */
    append(stream: ByteStream): void;
    /**
     * Append a "view" content to the current "Stream"
     * @param view A new "view" to append to current "stream"
     */
    appendView(view: Uint8Array): void;
    /**
     * Append a new char to the current "Stream"
     * @param char A new char to append to current "stream"
     */
    appendChar(char: number): void;
    /**
     * Append a new number to the current "Stream"
     * @param number A new unsigned 16-bit integer to append to current "stream"
     */
    appendUint16(number: number): void;
    /**
     * Append a new number to the current "Stream"
     * @param number A new unsigned 24-bit integer to append to current "stream"
     */
    appendUint24(number: number): void;
    /**
     * Append a new number to the current "Stream"
     * @param number A new unsigned 32-bit integer to append to current "stream"
     */
    appendUint32(number: number): void;
    /**
     * Append a new number to the current "Stream"
     * @param number A new signed 16-bit integer to append to current "stream"
     */
    appendInt16(number: number): void;
    /**
     * Append a new number to the current "Stream"
     * @param number A new signed 32-bit integer to append to current "stream"
     */
    appendInt32(number: number): void;
    /**
     * Get a block of data
     * @param size Size of the data block to get
     * @param changeLength Should we change "length" and "start" value after reading the data block
     * @returns
     */
    getBlock(size: number, changeLength?: boolean): Uint8Array;
    /**
     * Get 2-byte unsigned integer value
     * @param changeLength Should we change "length" and "start" value after reading the data block
     * @returns
     */
    getUint16(changeLength?: boolean): number;
    /**
     * Get 2-byte signed integer value
     * @param changeLength Should we change "length" and "start" value after reading the data block
     * @returns
     */
    getInt16(changeLength?: boolean): number;
    /**
     * Get 3-byte unsigned integer value
     * @param changeLength Should we change "length" and "start" value after reading the data block
     * @returns
     */
    getUint24(changeLength?: boolean): number;
    /**
     * Get 4-byte unsigned integer value
     * @param changeLength Should we change "length" and "start" value after reading the data block
     * @returns
     */
    getUint32(changeLength?: boolean): number;
    /**
     * Get 4-byte signed integer value
     * @param changeLength Should we change "length" and "start" value after reading the data block
     * @returns
     */
    getInt32(changeLength?: boolean): number;
    protected beforeAppend(size: number): void;
}
