import { ByteStream, FindFirstInResult, FindFirstNotInResult, FindFirstSequenceResult, FindPairedArraysResult, FindPairedPatternsResult, FindResult } from "./byte_stream";
export interface BitStreamViewParameters {
    view: Uint8Array;
    bitsCount?: number;
}
export interface BitStreamStreamParameters {
    byteStream: ByteStream;
    bitsCount?: number;
}
export interface BitStreamBufferParameters {
    buffer: ArrayBuffer;
    bitsCount?: number;
}
export interface BitStreamUint32Parameters {
    uint32: number;
    bitsCount?: number;
}
export interface BitStreamStringParameters {
    string: string;
    bitsCount?: number;
}
export declare type BitStreamParameters = BitStreamViewParameters | BitStreamStreamParameters | BitStreamBufferParameters | BitStreamUint32Parameters | BitStreamStringParameters;
export declare class BitStream {
    buffer: ArrayBuffer;
    view: Uint8Array;
    bitsCount: number;
    /**
     * Constructor for "BitStream" class
     * @param parameters
     */
    constructor(parameters?: BitStreamParameters);
    /**
     * Clear existing stream
     */
    clear(): void;
    /**
     * Initialize "BitStream" by data from existing "ByteStream"
     * @param stream
     */
    fromByteStream(stream: ByteStream): void;
    /**
     * Initialize "BitStream" object from existing "ArrayBuffer"
     * @param array The ArrayBuffer to copy from
     */
    fromArrayBuffer(array: ArrayBuffer): void;
    /**
     * Initialize "BitStream" object from existing "Uint8Array"
     * @param array The Uint8Array to copy from
     */
    fromUint8Array(array: Uint8Array): void;
    /**
     * Initialize "BitStream" object from existing bit string
     * @param string The string to initialize from
     */
    fromString(string: string): void;
    /**
     * Initialize "BitStream" object from existing uint32 number
     * @param number The string to initialize from
     */
    fromUint32(uint32: number): void;
    /**
     * Represent "BitStream" object content as a string
     * @param start Start number to convert to string from
     * @param length Length of BitStream to convert to string
     * @returns
     */
    toString(start?: null | number, length?: null | number): string;
    /**
     * Shift entire "BitStream" value right to number of bits
     * @param shift Number of bits to shift value
     * @param needShrink Need to shrink result or not
     */
    shiftRight(shift: number, needShrink?: boolean): void;
    /**
     * Shift entire "BitStream" value left to number of bits
     * @param shift Number of bits to shift value
     */
    shiftLeft(shift: number): void;
    /**
     * Return slice of existing "BitStream"
     * @param start Start position of the slice (in bits)
     * @param end End position of the slice (in bits)
     * @returns
     */
    slice(start?: number, end?: number): BitStream;
    /**
     * Return copy of existing "BitStream"
     * @param start Start position of the copy (in bits)
     * @param length Length of the copy (in bits)
     * @returns
     */
    copy(start?: number, length?: number): BitStream;
    /**
     * Shrink unnecessary bytes in current stream accordingly to "bitsCount" value
     */
    shrink(): void;
    /**
     * Reverse bits order in each byte in the stream
     *
     * Got it from here: http://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith32Bits
     */
    reverseBytes(): void;
    /**
     * Reverse all bits in entire "BitStream"
     */
    reverseValue(): void;
    /**
     * Trying to represent entire "BitStream" as an unsigned integer.
     * @return
     */
    getNumberValue(): number;
    /**
     * Find any bit pattern in "BitStream"
     * @param pattern Stream having pattern value
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @param backward Flag to search in backward order
     * @returns
     */
    findPattern(pattern: BitStream, start?: null | number, length?: null | number, backward?: boolean): number;
    /**
     * Find first position of any pattern from input array
     * @param patterns Array with patterns which should be found
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @param backward Flag to search in backward order
     */
    findFirstIn(patterns: BitStream[], start?: null | number, length?: null | number, backward?: boolean): FindFirstInResult;
    /**
     * Find all positions of any pattern from input array
     * @param patterns Array with patterns which should be found
     * @param start Start position to search from
     * @param length Length of byte block to search at
     */
    findAllIn(patterns: BitStream[], start?: null | number, length?: null | number): FindResult[];
    /**
     * Find all positions of a pattern
     * @param pattern Stream having pattern value
     * @param start Start position to search from
     * @param length Length of byte block to search at
     */
    findAllPatternIn(pattern: BitStream, start?: null | number, length?: null | number): -1 | number[];
    /**
     * Find first position of data, not included in patterns from input array
     * @param patterns Array with patterns which should be found
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @param backward Flag to search in backward order
     * @returns
     */
    findFirstNotIn(patterns: BitStream[], start?: null | number, length?: null | number, backward?: boolean): FindFirstNotInResult;
    /**
     * Find all positions of data, not included in patterns from input array
     * @param patterns Array with patterns which should be found
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @returns {Array}
     */
    findAllNotIn(patterns: BitStream[], start?: null | number, length?: null | number): FindFirstNotInResult[];
    /**
     * Find position of a sequence of any patterns from input array
     * @param patterns Array with patterns which should be found
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @param backward Flag to search in backward order
     */
    findFirstSequence(patterns: BitStream[], start?: null | number, length?: null | number, backward?: boolean): FindFirstSequenceResult;
    /**
     * Find position of a sequence of any patterns from input array
     * @param patterns Array with patterns which should be found
     * @param start Start position to search from
     * @param length Length of byte block to search at
     */
    findAllSequences(patterns: BitStream[], start?: null | number, length?: null | number): FindFirstSequenceResult[];
    /**
     * Find all paired patterns in the stream
     * @param leftPattern Left pattern to search for
     * @param rightPattern Right pattern to search for
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @returns
     */
    findPairedPatterns(leftPattern: BitStream, rightPattern: BitStream, start?: null | number, length?: null | number): FindPairedPatternsResult[];
    /**
     * Find all paired patterns in the stream
     * @param inputLeftPatterns Array of left patterns to search for
     * @param inputRightPatterns Array of right patterns to search for
     * @param start Start position to search from
     * @param length Length of byte block to search at
     */
    findPairedArrays(inputLeftPatterns: BitStream[], inputRightPatterns: BitStream[], start?: null | number, length?: null | number): FindPairedArraysResult[];
    /**
     * Replace one pattern with other
     * @param searchPattern The pattern to search for
     * @param replacePattern The pattern to replace initial pattern
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @returns
     */
    replacePattern(searchPattern: BitStream, replacePattern: BitStream, start?: null | number, length?: null | number): boolean;
    /**
     * Skip any pattern from input array
     * @param patterns Array with patterns which should be omitted
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @param backward Flag to search in backward order
     */
    skipPatterns(patterns: BitStream[], start?: null | number, length?: null | number, backward?: boolean): number;
    /**
     * Skip any pattern not from input array
     * @param patterns Array with patterns which should be omitted
     * @param start Start position to search from
     * @param length Length of byte block to search at
     * @param backward Flag to search in backward order
     */
    skipNotPatterns(patterns: BitStream[], start?: null | number, length?: null | number, backward?: boolean): number;
    /**
     * Append a new "BitStream" content to the current "BitStream"
     * @param stream A new "stream" to append to current "stream"
     */
    append(stream: BitStream): void;
}
