import { ByteStream } from "./byte_stream";
export interface ByteMapFunctionResult {
    status: number;
    length: number;
    value?: string | number;
}
export interface ByteMap {
    type: string;
    name: string;
    defaultValue?: number | string;
    maxlength: number;
    minlength: number;
    func: (array: Uint8Array) => ByteMapFunctionResult;
}
/**
 * Get parsed values from "byte map"
 * @param stream Stream to parse data from
 * @param map Object with information how to parse "byte map"
 * @param elements Number of elements in parsing byte map
 * @param start Start position to parse from
 * @param length Length of byte block to parse from
 */
export declare function parseByteMap(stream: ByteStream, map: ByteMap[], elements: number, start?: null | number, length?: null | number): Record<string, any>[];
