"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SeqBitStream = void 0;
const bit_stream_1 = require("./bit_stream");
class SeqBitStream {
    constructor(parameters = {}) {
        var _a;
        this._length = 0;
        this._start = 0;
        this.prevLength = 0;
        this.prevStart = 0;
        this.stream = ((_a = parameters.stream) === null || _a === void 0 ? void 0 : _a.slice()) || new bit_stream_1.BitStream();
        this.appendBlock = parameters.appendBlock || 0;
        if (parameters.start && parameters.start > 0) {
            this.start = parameters.start;
        }
        if (parameters.length && parameters.length > 0) {
            this.length = parameters.length;
        }
        this.backward = parameters.backward || false;
    }
    set start(value) {
        if (value > this.stream.bitsCount) {
            return;
        }
        this._length -= ((this.backward) ? (this._start - value) : (value - this._start));
        this._start = value;
        this.prevStart = this._start;
        this.prevLength = this._length;
    }
    get start() {
        return this._start;
    }
    set length(value) {
        if (value > this.stream.bitsCount) {
            return;
        }
        this.prevLength = this._length;
        this._length = value;
    }
    get length() {
        return this._length;
    }
    set stream(value) {
        this._stream = value;
        this.prevLength = this._length;
        this._length = value.bitsCount;
        this.prevStart = this._start;
        this._start = (this.backward) ? this.length : 0;
    }
    get stream() {
        return this._stream;
    }
    getBits(length = null) {
        if (length === null) {
            length = 0;
        }
        else if (length === 0) {
            return new bit_stream_1.BitStream();
        }
        if ((this.start + length) > this.stream.bitsCount) {
            length = (this.stream.bitsCount - this.start);
        }
        let result;
        if (this.backward) {
            result = this.stream.copy(this.start - length, length);
            this.start -= result.bitsCount;
        }
        else {
            result = this.stream.copy(this.start, length);
            this.start += result.bitsCount;
        }
        return result;
    }
    getBitsString(length) {
        return this.getBits(length).toString();
    }
    getBitsReversedValue(length) {
        const initialValue = this.getBitsString(length);
        const initialValueLength = initialValue.length;
        let byteIndex;
        const initialOffset = 8 - (initialValueLength % 8);
        const reversedValue = new Array(initialValueLength);
        const value = new Uint32Array(1);
        const valueView = new Uint8Array(value.buffer, 0, 4);
        let i;
        if (initialValueLength > 32) {
            return (-1);
        }
        if (length == 32) {
            byteIndex = 3;
        }
        else {
            byteIndex = ((initialValueLength - 1) >> 3);
        }
        for (i = 0; i < initialValueLength; i++) {
            reversedValue[initialValueLength - 1 - i] = initialValue[i];
        }
        for (i = initialOffset; i < (initialOffset + initialValueLength); i++) {
            if (reversedValue[i - initialOffset] == "1") {
                valueView[byteIndex] |= 0x01 << (7 - (i % 8));
            }
            if (i && (((i + 1) % 8) == 0)) {
                byteIndex--;
            }
        }
        return value[0];
    }
    toString() {
        const streamToDisplay = this.stream.copy(this.start, this.length);
        return streamToDisplay.toString();
    }
}
exports.SeqBitStream = SeqBitStream;
