import { ByteStream } from "./byte_stream";
const pow2_24 = 16777216;
export class SeqStream {
    constructor(parameters = {}) {
        this._stream = new ByteStream();
        this._length = 0;
        this._start = 0;
        this.backward = false;
        this.appendBlock = 0;
        this.prevLength = 0;
        this.prevStart = 0;
        if ("view" in parameters) {
            this.stream = new ByteStream({ view: parameters.view });
        }
        else if ("buffer" in parameters) {
            this.stream = new ByteStream({ buffer: parameters.buffer });
        }
        else if ("string" in parameters) {
            this.stream = new ByteStream({ string: parameters.string });
        }
        else if ("hexstring" in parameters) {
            this.stream = new ByteStream({ hexstring: parameters.hexstring });
        }
        else if ("stream" in parameters) {
            this.stream = parameters.stream.slice();
        }
        else {
            this.stream = new ByteStream();
        }
        if ("backward" in parameters && parameters.backward) {
            this.backward = parameters.backward;
            this._start = this.stream.length;
        }
        if ("length" in parameters && parameters.length > 0) {
            this._length = parameters.length;
        }
        if ("start" in parameters && parameters.start && parameters.start > 0) {
            this._start = parameters.start;
        }
        if ("appendBlock" in parameters && parameters.appendBlock && parameters.appendBlock > 0) {
            this.appendBlock = parameters.appendBlock;
        }
    }
    set stream(value) {
        this._stream = value;
        this.prevLength = this._length;
        this._length = value.length;
        this.prevStart = this._start;
        this._start = 0;
    }
    get stream() {
        return this._stream;
    }
    set length(value) {
        this.prevLength = this._length;
        this._length = value;
    }
    get length() {
        if (this.appendBlock) {
            return this.start;
        }
        return this._length;
    }
    set start(value) {
        if (value > this.stream.length)
            return;
        this.prevStart = this._start;
        this.prevLength = this._length;
        this._length -= (this.backward) ? (this._start - value) : (value - this._start);
        this._start = value;
    }
    get start() {
        return this._start;
    }
    get buffer() {
        return this._stream.buffer.slice(0, this._length);
    }
    resetPosition() {
        this._start = this.prevStart;
        this._length = this.prevLength;
    }
    findPattern(pattern, gap = null) {
        if ((gap == null) || (gap > this.length)) {
            gap = this.length;
        }
        const result = this.stream.findPattern(pattern, this.start, this.length, this.backward);
        if (result == (-1))
            return result;
        if (this.backward) {
            if (result < (this.start - pattern.length - gap)) {
                return (-1);
            }
        }
        else {
            if (result > (this.start + pattern.length + gap)) {
                return (-1);
            }
        }
        this.start = result;
        return result;
    }
    findFirstIn(patterns, gap = null) {
        if ((gap == null) || (gap > this.length)) {
            gap = this.length;
        }
        const result = this.stream.findFirstIn(patterns, this.start, this.length, this.backward);
        if (result.id == (-1))
            return result;
        if (this.backward) {
            if (result.position < (this.start - patterns[result.id].length - gap)) {
                return {
                    id: (-1),
                    position: (this.backward) ? 0 : (this.start + this.length)
                };
            }
        }
        else {
            if (result.position > (this.start + patterns[result.id].length + gap)) {
                return {
                    id: (-1),
                    position: (this.backward) ? 0 : (this.start + this.length)
                };
            }
        }
        this.start = result.position;
        return result;
    }
    findAllIn(patterns) {
        const start = (this.backward) ? (this.start - this.length) : this.start;
        return this.stream.findAllIn(patterns, start, this.length);
    }
    findFirstNotIn(patterns, gap = null) {
        if ((gap == null) || (gap > this._length)) {
            gap = this._length;
        }
        const result = this._stream.findFirstNotIn(patterns, this._start, this._length, this.backward);
        if ((result.left.id == (-1)) && (result.right.id == (-1))) {
            return result;
        }
        if (this.backward) {
            if (result.right.id != (-1)) {
                if (result.right.position < (this._start - patterns[result.right.id].length - gap)) {
                    return {
                        left: {
                            id: (-1),
                            position: this._start
                        },
                        right: {
                            id: (-1),
                            position: 0
                        },
                        value: new ByteStream()
                    };
                }
            }
        }
        else {
            if (result.left.id != (-1)) {
                if (result.left.position > (this._start + patterns[result.left.id].length + gap)) {
                    return {
                        left: {
                            id: (-1),
                            position: this._start
                        },
                        right: {
                            id: (-1),
                            position: 0
                        },
                        value: new ByteStream()
                    };
                }
            }
        }
        if (this.backward) {
            if (result.left.id == (-1)) {
                this.start = 0;
            }
            else {
                this.start = result.left.position;
            }
        }
        else {
            if (result.right.id == (-1)) {
                this.start = (this._start + this._length);
            }
            else {
                this.start = result.right.position;
            }
        }
        return result;
    }
    findAllNotIn(patterns) {
        const start = (this.backward) ? (this._start - this._length) : this._start;
        return this._stream.findAllNotIn(patterns, start, this._length);
    }
    findFirstSequence(patterns, length = null, gap = null) {
        if ((length == null) || (length > this._length)) {
            length = this._length;
        }
        if ((gap == null) || (gap > length)) {
            gap = length;
        }
        const result = this._stream.findFirstSequence(patterns, this._start, length, this.backward);
        if (result.value.length == 0) {
            return result;
        }
        if (this.backward) {
            if (result.position < (this._start - result.value.length - gap)) {
                return {
                    position: (-1),
                    value: new ByteStream()
                };
            }
        }
        else {
            if (result.position > (this._start + result.value.length + gap)) {
                return {
                    position: (-1),
                    value: new ByteStream()
                };
            }
        }
        this.start = result.position;
        return result;
    }
    findAllSequences(patterns) {
        const start = (this.backward) ? (this.start - this.length) : this.start;
        return this.stream.findAllSequences(patterns, start, this.length);
    }
    findPairedPatterns(leftPattern, rightPattern, gap = null) {
        if ((gap == null) || (gap > this.length)) {
            gap = this.length;
        }
        const start = (this.backward) ? (this.start - this.length) : this.start;
        const result = this.stream.findPairedPatterns(leftPattern, rightPattern, start, this.length);
        if (result.length) {
            if (this.backward) {
                if (result[0].right < (this.start - rightPattern.length - gap)) {
                    return [];
                }
            }
            else {
                if (result[0].left > (this.start + leftPattern.length + gap)) {
                    return [];
                }
            }
        }
        return result;
    }
    findPairedArrays(leftPatterns, rightPatterns, gap = null) {
        if ((gap == null) || (gap > this.length)) {
            gap = this.length;
        }
        const start = (this.backward) ? (this.start - this.length) : this.start;
        const result = this.stream.findPairedArrays(leftPatterns, rightPatterns, start, this.length);
        if (result.length) {
            if (this.backward) {
                if (result[0].right.position < (this.start - rightPatterns[result[0].right.id].length - gap)) {
                    return [];
                }
            }
            else {
                if (result[0].left.position > (this.start + leftPatterns[result[0].left.id].length + gap)) {
                    return [];
                }
            }
        }
        return result;
    }
    replacePattern(searchPattern, replacePattern) {
        const start = (this.backward) ? (this.start - this.length) : this.start;
        return this.stream.replacePattern(searchPattern, replacePattern, start, this.length);
    }
    skipPatterns(patterns) {
        const result = this.stream.skipPatterns(patterns, this.start, this.length, this.backward);
        this.start = result;
        return result;
    }
    skipNotPatterns(patterns) {
        const result = this.stream.skipNotPatterns(patterns, this.start, this.length, this.backward);
        if (result == (-1))
            return (-1);
        this.start = result;
        return result;
    }
    append(stream) {
        this.beforeAppend(stream.length);
        this._stream.view.set(stream.view, this._start);
        this._length += (stream.length * 2);
        this.start = (this._start + stream.length);
        this.prevLength -= (stream.length * 2);
    }
    appendView(view) {
        this.beforeAppend(view.length);
        this._stream.view.set(view, this._start);
        this._length += (view.length * 2);
        this.start = (this._start + view.length);
        this.prevLength -= (view.length * 2);
    }
    appendChar(char) {
        this.beforeAppend(1);
        this._stream.view[this._start] = char;
        this._length += 2;
        this.start = (this._start + 1);
        this.prevLength -= 2;
    }
    appendUint16(number) {
        this.beforeAppend(2);
        const value = new Uint16Array([number]);
        const view = new Uint8Array(value.buffer);
        this.stream.view[this._start] = view[1];
        this._stream.view[this._start + 1] = view[0];
        this._length += 4;
        this.start = this._start + 2;
        this.prevLength -= 4;
    }
    appendUint24(number) {
        this.beforeAppend(3);
        const value = new Uint32Array([number]);
        const view = new Uint8Array(value.buffer);
        this._stream.view[this._start] = view[2];
        this._stream.view[this._start + 1] = view[1];
        this._stream.view[this._start + 2] = view[0];
        this._length += 6;
        this.start = (this._start + 3);
        this.prevLength -= 6;
    }
    appendUint32(number) {
        this.beforeAppend(4);
        const value = new Uint32Array([number]);
        const view = new Uint8Array(value.buffer);
        this._stream.view[this._start] = view[3];
        this._stream.view[this._start + 1] = view[2];
        this._stream.view[this._start + 2] = view[1];
        this._stream.view[this._start + 3] = view[0];
        this._length += 8;
        this.start = (this._start + 4);
        this.prevLength -= 8;
    }
    appendInt16(number) {
        this.beforeAppend(2);
        const value = new Int16Array([number]);
        const view = new Uint8Array(value.buffer);
        this._stream.view[this._start] = view[1];
        this._stream.view[this._start + 1] = view[0];
        this._length += 4;
        this.start = (this._start + 2);
        this.prevLength -= 4;
    }
    appendInt32(number) {
        this.beforeAppend(4);
        const value = new Int32Array([number]);
        const view = new Uint8Array(value.buffer);
        this._stream.view[this._start] = view[3];
        this._stream.view[this._start + 1] = view[2];
        this._stream.view[this._start + 2] = view[1];
        this._stream.view[this._start + 3] = view[0];
        this._length += 8;
        this.start = (this._start + 4);
        this.prevLength -= 8;
    }
    getBlock(size, changeLength = true) {
        if (this._length <= 0) {
            return new Uint8Array(0);
        }
        if (this._length < size) {
            size = this._length;
        }
        let result;
        if (this.backward) {
            const view = this._stream.view.subarray(this._length - size, this._length);
            result = new Uint8Array(size);
            for (let i = 0; i < size; i++) {
                result[size - 1 - i] = view[i];
            }
        }
        else {
            result = this._stream.view.subarray(this._start, this._start + size);
        }
        if (changeLength) {
            this.start += ((this.backward) ? ((-1) * size) : size);
        }
        return result;
    }
    getUint16(changeLength = true) {
        const block = this.getBlock(2, changeLength);
        if (block.length < 2)
            return 0;
        return (block[0] << 8) | block[1];
    }
    getInt16(changeLength = true) {
        const num = this.getUint16(changeLength);
        const negative = 0x8000;
        if (num & negative) {
            return -(negative - (num ^ negative));
        }
        return num;
    }
    getUint24(changeLength = true) {
        const block = this.getBlock(4, changeLength);
        if (block.length < 3)
            return 0;
        return (block[0] << 16) |
            (block[1] << 8) |
            block[2];
    }
    getUint32(changeLength = true) {
        const block = this.getBlock(4, changeLength);
        if (block.length < 4)
            return 0;
        return (block[0] * pow2_24) +
            (block[1] << 16) +
            (block[2] << 8) +
            block[3];
    }
    getInt32(changeLength = true) {
        const num = this.getUint32(changeLength);
        const negative = 0x80000000;
        if (num & negative) {
            return -(negative - (num ^ negative));
        }
        return num;
    }
    beforeAppend(size) {
        if ((this._start + size) > this._stream.length) {
            if (size > this.appendBlock) {
                this.appendBlock = size + SeqStream.APPEND_BLOCK;
            }
            this._stream.realloc(this._stream.length + this.appendBlock);
        }
    }
}
SeqStream.APPEND_BLOCK = 1000;
