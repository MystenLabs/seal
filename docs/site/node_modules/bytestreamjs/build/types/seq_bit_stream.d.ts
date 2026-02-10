import { BitStream } from "./bit_stream";
export interface SeqBitStreamParameters {
    backward?: boolean;
    length?: number;
    start?: number;
    appendBlock?: number;
    stream?: BitStream;
}
export declare class SeqBitStream {
    private _length;
    private _start;
    private _stream;
    prevLength: number;
    prevStart: number;
    backward: boolean;
    appendBlock: number;
    constructor(parameters?: SeqBitStreamParameters);
    set start(value: number);
    get start(): number;
    set length(value: number);
    get length(): number;
    set stream(value: BitStream);
    get stream(): BitStream;
    /**
     * Get next "length" bits from the stream
     * @param length Number of bits to read
     * @returns
     */
    getBits(length?: null | number): BitStream;
    /**
     * Get string representation for the next "length" bits from the stream
     * @param length Number of bits to read
     * @returns
     */
    getBitsString(length: number): string;
    /**
     * Get number value representation of the next "length" bits from the stream, preliminary reversed
     * @param length Number of bits to read
     * @returns
     */
    getBitsReversedValue(length: number): number;
    /**
     * Represent remaining bits in "BitStream" as a string
     * @return
     */
    toString(): string;
}
