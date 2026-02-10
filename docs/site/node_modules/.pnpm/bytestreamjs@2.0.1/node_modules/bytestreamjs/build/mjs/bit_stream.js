import { bitsToStringArray } from "./bit";
import { ByteStream } from "./byte_stream";
export class BitStream {
    constructor(parameters) {
        this.buffer = new ArrayBuffer(0);
        this.view = new Uint8Array(this.buffer);
        this.bitsCount = 0;
        if (parameters) {
            if ("byteStream" in parameters) {
                this.fromByteStream(parameters.byteStream);
            }
            if ("view" in parameters) {
                this.fromUint8Array(parameters.view);
            }
            if ("buffer" in parameters) {
                this.fromArrayBuffer(parameters.buffer);
            }
            if ("string" in parameters) {
                this.fromString(parameters.string);
            }
            if ("uint32" in parameters) {
                this.fromUint32(parameters.uint32);
            }
            if ("bitsCount" in parameters && parameters.bitsCount) {
                this.bitsCount = parameters.bitsCount;
            }
        }
    }
    clear() {
        this.buffer = new ArrayBuffer(0);
        this.view = new Uint8Array(this.buffer);
        this.bitsCount = 0;
    }
    fromByteStream(stream) {
        this.fromUint8Array(stream.view);
    }
    fromArrayBuffer(array) {
        this.buffer = array;
        this.view = new Uint8Array(array);
        this.bitsCount = this.view.length << 3;
    }
    fromUint8Array(array) {
        this.fromArrayBuffer(new Uint8Array(array).buffer);
    }
    fromString(string) {
        const stringLength = string.length;
        this.buffer = new ArrayBuffer((stringLength >> 3) + ((stringLength % 8) ? 1 : 0));
        this.view = new Uint8Array(this.buffer);
        this.bitsCount = ((stringLength >> 3) + 1) << 3;
        let byteIndex = 0;
        for (let i = 0; i < stringLength; i++) {
            if (string[i] == "1")
                this.view[byteIndex] |= 1 << (7 - (i % 8));
            if (i && (((i + 1) % 8) == 0))
                byteIndex++;
        }
        if (stringLength % 8)
            this.shiftRight(8 - (stringLength % 8));
        this.bitsCount = stringLength;
    }
    fromUint32(uint32) {
        this.buffer = new ArrayBuffer(4);
        this.view = new Uint8Array(this.buffer);
        const value = new Uint32Array([uint32]);
        const view = new Uint8Array(value.buffer);
        for (let i = 3; i >= 0; i--)
            this.view[i] = view[3 - i];
        this.bitsCount = 32;
    }
    toString(start, length) {
        if (start == null) {
            start = 0;
        }
        if ((start >= this.view.length) || (start < 0)) {
            start = 0;
        }
        if (length == null) {
            length = this.view.length - start;
        }
        if ((length >= this.view.length) || (length < 0)) {
            length = this.view.length - start;
        }
        const result = [];
        for (let i = start; i < (start + length); i++) {
            result.push(bitsToStringArray[this.view[i]]);
        }
        return result.join("").substring((this.view.length << 3) - this.bitsCount);
    }
    shiftRight(shift, needShrink = true) {
        if (this.view.length == 0) {
            return;
        }
        if ((shift < 0) || (shift > 8)) {
            throw new Error("The \"shift\" parameter must be in range 0-8");
        }
        if (shift > this.bitsCount) {
            throw new Error("The \"shift\" parameter can not be bigger than \"this.bitsCount\"");
        }
        const shiftMask = 0xFF >> (8 - shift);
        this.view[this.view.length - 1] >>= shift;
        for (let i = (this.view.length - 2); i >= 0; i--) {
            this.view[i + 1] |= (this.view[i] & shiftMask) << (8 - shift);
            this.view[i] >>= shift;
        }
        this.bitsCount -= shift;
        if (this.bitsCount == 0) {
            this.clear();
        }
        if (needShrink) {
            this.shrink();
        }
    }
    shiftLeft(shift) {
        if (this.view.length == 0) {
            return;
        }
        if ((shift < 0) || (shift > 8)) {
            throw new Error("The \"shift\" parameter must be in range 0-8");
        }
        if (shift > this.bitsCount) {
            throw new Error("The \"shift\" parameter can not be bigger than \"this.bitsCount\"");
        }
        const bitsOffset = this.bitsCount & 0x07;
        if (bitsOffset > shift) {
            this.view[0] &= 0xFF >> (bitsOffset + shift);
        }
        else {
            const view = this.view.slice(1);
            view[0] &= 0xFF >> (shift - bitsOffset);
            this.buffer = view.buffer;
            this.view = view;
        }
        this.bitsCount -= shift;
        if (this.bitsCount == 0) {
            this.clear();
        }
    }
    slice(start = 0, end = 0) {
        let valueShift = 0;
        if (this.bitsCount % 8) {
            valueShift = (8 - (this.bitsCount % 8));
        }
        start += valueShift;
        end += valueShift;
        const maxEnd = (this.view.length << 3) - 1;
        if ((start < 0) || (start > maxEnd)) {
            return new BitStream();
        }
        if (!end) {
            end = maxEnd;
        }
        if ((end < 0) || (end > maxEnd)) {
            return new BitStream();
        }
        if ((end - start + 1) > this.bitsCount) {
            return new BitStream();
        }
        const startIndex = start >> 3;
        const startOffset = start & 0x07;
        const endIndex = end >> 3;
        const endOffset = end & 0x07;
        const bitsLength = ((endIndex - startIndex) == 0) ? 1 : (endIndex - startIndex + 1);
        const result = new BitStream({
            buffer: this.buffer.slice(startIndex, startIndex + bitsLength),
            bitsCount: bitsLength << 3,
        });
        result.view[0] &= (0xFF >> startOffset);
        result.view[bitsLength] &= (0xFF << (7 - endOffset));
        if (7 - endOffset) {
            result.shiftRight(7 - endOffset, false);
        }
        result.bitsCount = (end - start + 1);
        result.shrink();
        return result;
    }
    copy(start = 0, length = 0) {
        const maxEnd = (this.view.length << 3) - 1;
        if ((start < 0) || (start > maxEnd)) {
            return new BitStream();
        }
        if (!length) {
            length = (this.view.length << 3) - start - 1;
        }
        if (length > this.bitsCount) {
            return new BitStream();
        }
        return this.slice(start, start + length - 1);
    }
    shrink() {
        const currentLength = (this.bitsCount >> 3) + ((this.bitsCount % 8) ? 1 : 0);
        if (currentLength < this.view.length) {
            const view = this.view.slice(this.view.length - currentLength, (this.view.length - currentLength) + currentLength);
            this.view = view;
            this.buffer = view.buffer;
        }
    }
    reverseBytes() {
        for (let i = 0; i < this.view.length; i++) {
            this.view[i] = ((this.view[i] * 0x0802 & 0x22110) | (this.view[i] * 0x8020 & 0x88440)) * 0x10101 >> 16;
        }
        if (this.bitsCount % 8) {
            const currentLength = (this.bitsCount >> 3) + ((this.bitsCount % 8) ? 1 : 0);
            this.view[this.view.length - currentLength] >>= (8 - (this.bitsCount & 0x07));
        }
    }
    reverseValue() {
        const initialValue = this.toString();
        const initialValueLength = initialValue.length;
        const reversedValue = new Array(initialValueLength);
        for (let i = 0; i < initialValueLength; i++) {
            reversedValue[initialValueLength - 1 - i] = initialValue[i];
        }
        this.fromString(reversedValue.join(""));
    }
    getNumberValue() {
        const byteLength = (this.view.length - 1);
        if (byteLength > 3) {
            return (-1);
        }
        if (byteLength == (-1)) {
            return 0;
        }
        const value = new Uint32Array(1);
        const view = new Uint8Array(value.buffer);
        for (let i = byteLength; i >= 0; i--) {
            view[byteLength - i] = this.view[i];
        }
        return value[0];
    }
    findPattern(pattern, start, length, backward) {
        const stringStream = new ByteStream({
            string: this.toString(),
        });
        const stringPattern = new ByteStream({
            string: pattern.toString()
        });
        return stringStream.findPattern(stringPattern, start, length, backward);
    }
    findFirstIn(patterns, start, length, backward) {
        const stringStream = new ByteStream({
            string: this.toString(),
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.findFirstIn(stringPatterns, start, length, backward);
    }
    findAllIn(patterns, start, length) {
        const stringStream = new ByteStream({
            string: this.toString()
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.findAllIn(stringPatterns, start, length);
    }
    findAllPatternIn(pattern, start, length) {
        const stringStream = new ByteStream({
            string: this.toString()
        });
        const stringPattern = new ByteStream({
            string: pattern.toString()
        });
        return stringStream.findAllPatternIn(stringPattern, start, length);
    }
    findFirstNotIn(patterns, start, length, backward) {
        const stringStream = new ByteStream({
            string: this.toString()
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.findFirstNotIn(stringPatterns, start, length, backward);
    }
    findAllNotIn(patterns, start, length) {
        const stringStream = new ByteStream({
            string: this.toString()
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.findAllNotIn(stringPatterns, start, length);
    }
    findFirstSequence(patterns, start, length, backward) {
        const stringStream = new ByteStream({
            string: this.toString()
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.findFirstSequence(stringPatterns, start, length, backward);
    }
    findAllSequences(patterns, start, length) {
        const stringStream = new ByteStream({
            string: this.toString()
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.findAllSequences(stringPatterns, start, length);
    }
    findPairedPatterns(leftPattern, rightPattern, start, length) {
        const stringStream = new ByteStream({
            string: this.toString()
        });
        const stringLeftPattern = new ByteStream({
            string: leftPattern.toString()
        });
        const stringRightPattern = new ByteStream({
            string: rightPattern.toString()
        });
        return stringStream.findPairedPatterns(stringLeftPattern, stringRightPattern, start, length);
    }
    findPairedArrays(inputLeftPatterns, inputRightPatterns, start, length) {
        const stringStream = new ByteStream({
            string: this.toString()
        });
        const stringLeftPatterns = new Array(inputLeftPatterns.length);
        for (let i = 0; i < inputLeftPatterns.length; i++) {
            stringLeftPatterns[i] = new ByteStream({
                string: inputLeftPatterns[i].toString()
            });
        }
        const stringRightPatterns = new Array(inputRightPatterns.length);
        for (let i = 0; i < inputRightPatterns.length; i++) {
            stringRightPatterns[i] = new ByteStream({
                string: inputRightPatterns[i].toString()
            });
        }
        return stringStream.findPairedArrays(stringLeftPatterns, stringRightPatterns, start, length);
    }
    replacePattern(searchPattern, replacePattern, start, length) {
        const stringStream = new ByteStream({
            string: this.toString()
        });
        const stringSearchPattern = new ByteStream({
            string: searchPattern.toString()
        });
        const stringReplacePattern = new ByteStream({
            string: replacePattern.toString()
        });
        if (stringStream.replacePattern(stringSearchPattern, stringReplacePattern, start, length)) {
            this.fromString(stringStream.toString());
            return true;
        }
        return false;
    }
    skipPatterns(patterns, start, length, backward) {
        const stringStream = new ByteStream({
            string: this.toString()
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.skipPatterns(stringPatterns, start, length, backward);
    }
    skipNotPatterns(patterns, start, length, backward) {
        const stringStream = new ByteStream({
            string: this.toString()
        });
        const stringPatterns = new Array(patterns.length);
        for (let i = 0; i < patterns.length; i++) {
            stringPatterns[i] = new ByteStream({
                string: patterns[i].toString()
            });
        }
        return stringStream.skipNotPatterns(stringPatterns, start, length, backward);
    }
    append(stream) {
        this.fromString([
            this.toString(),
            stream.toString()
        ].join(""));
    }
}
