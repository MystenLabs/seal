"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ByteStream = void 0;
class ByteStream {
    constructor(parameters = {}) {
        if ("view" in parameters) {
            this.fromUint8Array(parameters.view);
        }
        else if ("buffer" in parameters) {
            this.fromArrayBuffer(parameters.buffer);
        }
        else if ("string" in parameters) {
            this.fromString(parameters.string);
        }
        else if ("hexstring" in parameters) {
            this.fromHexString(parameters.hexstring);
        }
        else {
            if ("length" in parameters && parameters.length > 0) {
                this.length = parameters.length;
                if (parameters.stub) {
                    for (let i = 0; i < this._view.length; i++) {
                        this._view[i] = parameters.stub;
                    }
                }
            }
            else {
                this.length = 0;
            }
        }
    }
    set buffer(value) {
        this._buffer = value;
        this._view = new Uint8Array(this._buffer);
    }
    get buffer() {
        return this._buffer;
    }
    set view(value) {
        this._buffer = new ArrayBuffer(value.length);
        this._view = new Uint8Array(this._buffer);
        this._view.set(value);
    }
    get view() {
        return this._view;
    }
    get length() {
        return this.view.byteLength;
    }
    set length(value) {
        this._buffer = new ArrayBuffer(value);
        this._view = new Uint8Array(this._buffer);
    }
    clear() {
        this._buffer = new ArrayBuffer(0);
        this._view = new Uint8Array(this._buffer);
    }
    fromArrayBuffer(array) {
        this._buffer = array;
        this._view = new Uint8Array(this._buffer);
    }
    fromUint8Array(array) {
        this.fromArrayBuffer(new Uint8Array(array).buffer);
    }
    fromString(string) {
        const stringLength = string.length;
        this.length = stringLength;
        for (let i = 0; i < stringLength; i++)
            this.view[i] = string.charCodeAt(i);
    }
    toString(start = 0, length = (this.view.length - start)) {
        let result = "";
        if ((start >= this.view.length) || (start < 0)) {
            start = 0;
        }
        if ((length >= this.view.length) || (length < 0)) {
            length = this.view.length - start;
        }
        for (let i = start; i < (start + length); i++)
            result += String.fromCharCode(this.view[i]);
        return result;
    }
    fromHexString(hexString) {
        const stringLength = hexString.length;
        this.buffer = new ArrayBuffer(stringLength >> 1);
        this.view = new Uint8Array(this.buffer);
        const hexMap = new Map();
        hexMap.set("0", 0x00);
        hexMap.set("1", 0x01);
        hexMap.set("2", 0x02);
        hexMap.set("3", 0x03);
        hexMap.set("4", 0x04);
        hexMap.set("5", 0x05);
        hexMap.set("6", 0x06);
        hexMap.set("7", 0x07);
        hexMap.set("8", 0x08);
        hexMap.set("9", 0x09);
        hexMap.set("A", 0x0A);
        hexMap.set("a", 0x0A);
        hexMap.set("B", 0x0B);
        hexMap.set("b", 0x0B);
        hexMap.set("C", 0x0C);
        hexMap.set("c", 0x0C);
        hexMap.set("D", 0x0D);
        hexMap.set("d", 0x0D);
        hexMap.set("E", 0x0E);
        hexMap.set("e", 0x0E);
        hexMap.set("F", 0x0F);
        hexMap.set("f", 0x0F);
        let j = 0;
        let temp = 0x00;
        for (let i = 0; i < stringLength; i++) {
            if (!(i % 2)) {
                temp = hexMap.get(hexString.charAt(i)) << 4;
            }
            else {
                temp |= hexMap.get(hexString.charAt(i));
                this.view[j] = temp;
                j++;
            }
        }
    }
    toHexString(start = 0, length = (this.view.length - start)) {
        let result = "";
        if ((start >= this.view.length) || (start < 0)) {
            start = 0;
        }
        if ((length >= this.view.length) || (length < 0)) {
            length = this.view.length - start;
        }
        for (let i = start; i < (start + length); i++) {
            const str = this.view[i].toString(16).toUpperCase();
            result = result + ((str.length == 1) ? "0" : "") + str;
        }
        return result;
    }
    copy(start = 0, length = (this.length - start)) {
        if (!start && !this.length) {
            return new ByteStream();
        }
        if ((start < 0) || (start > (this.length - 1))) {
            throw new Error(`Wrong start position: ${start}`);
        }
        const stream = new ByteStream({
            buffer: this._buffer.slice(start, start + length)
        });
        return stream;
    }
    slice(start = 0, end = this.length) {
        if (!start && !this.length) {
            return new ByteStream();
        }
        if ((start < 0) || (start > (this.length - 1))) {
            throw new Error(`Wrong start position: ${start}`);
        }
        const stream = new ByteStream({
            buffer: this._buffer.slice(start, end),
        });
        return stream;
    }
    realloc(size) {
        const buffer = new ArrayBuffer(size);
        const view = new Uint8Array(buffer);
        if (size > this._view.length)
            view.set(this._view);
        else {
            view.set(new Uint8Array(this._buffer, 0, size));
        }
        this._buffer = buffer;
        this._view = new Uint8Array(this._buffer);
    }
    append(stream) {
        const initialSize = this.length;
        const streamViewLength = stream.length;
        const subarrayView = stream._view.subarray();
        this.realloc(initialSize + streamViewLength);
        this._view.set(subarrayView, initialSize);
    }
    insert(stream, start = 0, length = (this.length - start)) {
        if (start > (this.length - 1))
            return false;
        if (length > (this.length - start)) {
            length = this.length - start;
        }
        if (length > stream.length) {
            length = stream.length;
        }
        if (length == stream.length)
            this._view.set(stream._view, start);
        else {
            this._view.set(stream._view.subarray(0, length), start);
        }
        return true;
    }
    isEqual(stream) {
        if (this.length != stream.length)
            return false;
        for (let i = 0; i < stream.length; i++) {
            if (this.view[i] != stream.view[i])
                return false;
        }
        return true;
    }
    isEqualView(view) {
        if (view.length != this.view.length)
            return false;
        for (let i = 0; i < view.length; i++) {
            if (this.view[i] != view[i])
                return false;
        }
        return true;
    }
    findPattern(pattern, start_, length_, backward_) {
        const { start, length, backward } = this.prepareFindParameters(start_, length_, backward_);
        const patternLength = pattern.length;
        if (patternLength > length) {
            return (-1);
        }
        const patternArray = [];
        for (let i = 0; i < patternLength; i++)
            patternArray.push(pattern.view[i]);
        for (let i = 0; i <= (length - patternLength); i++) {
            let equal = true;
            const equalStart = (backward) ? (start - patternLength - i) : (start + i);
            for (let j = 0; j < patternLength; j++) {
                if (this.view[j + equalStart] != patternArray[j]) {
                    equal = false;
                    break;
                }
            }
            if (equal) {
                return (backward) ? (start - patternLength - i) : (start + patternLength + i);
            }
        }
        return (-1);
    }
    findFirstIn(patterns, start_, length_, backward_) {
        const { start, length, backward } = this.prepareFindParameters(start_, length_, backward_);
        const result = {
            id: (-1),
            position: (backward) ? 0 : (start + length),
            length: 0
        };
        for (let i = 0; i < patterns.length; i++) {
            const position = this.findPattern(patterns[i], start, length, backward);
            if (position != (-1)) {
                let valid = false;
                const patternLength = patterns[i].length;
                if (backward) {
                    if ((position - patternLength) >= (result.position - result.length))
                        valid = true;
                }
                else {
                    if ((position - patternLength) <= (result.position - result.length))
                        valid = true;
                }
                if (valid) {
                    result.position = position;
                    result.id = i;
                    result.length = patternLength;
                }
            }
        }
        return result;
    }
    findAllIn(patterns, start_, length_) {
        let { start, length } = this.prepareFindParameters(start_, length_);
        const result = [];
        let patternFound = {
            id: (-1),
            position: start
        };
        do {
            const position = patternFound.position;
            patternFound = this.findFirstIn(patterns, patternFound.position, length);
            if (patternFound.id == (-1)) {
                break;
            }
            length -= (patternFound.position - position);
            result.push({
                id: patternFound.id,
                position: patternFound.position
            });
        } while (true);
        return result;
    }
    findAllPatternIn(pattern, start_, length_) {
        const { start, length } = this.prepareFindParameters(start_, length_);
        const result = [];
        const patternLength = pattern.length;
        if (patternLength > length) {
            return (-1);
        }
        const patternArray = Array.from(pattern.view);
        for (let i = 0; i <= (length - patternLength); i++) {
            let equal = true;
            const equalStart = start + i;
            for (let j = 0; j < patternLength; j++) {
                if (this.view[j + equalStart] != patternArray[j]) {
                    equal = false;
                    break;
                }
            }
            if (equal) {
                result.push(start + patternLength + i);
                i += (patternLength - 1);
            }
        }
        return result;
    }
    findFirstNotIn(patterns, start_, length_, backward_) {
        let { start, length, backward } = this.prepareFindParameters(start_, length_, backward_);
        const result = {
            left: {
                id: (-1),
                position: start
            },
            right: {
                id: (-1),
                position: 0
            },
            value: new ByteStream()
        };
        let currentLength = length;
        while (currentLength > 0) {
            result.right = this.findFirstIn(patterns, (backward) ? (start - length + currentLength) : (start + length - currentLength), currentLength, backward);
            if (result.right.id == (-1)) {
                length = currentLength;
                if (backward) {
                    start -= length;
                }
                else {
                    start = result.left.position;
                }
                result.value = new ByteStream({
                    buffer: this._buffer.slice(start, start + length),
                });
                break;
            }
            if (result.right.position != ((backward) ? (result.left.position - patterns[result.right.id].length) : (result.left.position + patterns[result.right.id].length))) {
                if (backward) {
                    start = result.right.position + patterns[result.right.id].length;
                    length = result.left.position - result.right.position - patterns[result.right.id].length;
                }
                else {
                    start = result.left.position;
                    length = result.right.position - result.left.position - patterns[result.right.id].length;
                }
                result.value = new ByteStream({
                    buffer: this._buffer.slice(start, start + length),
                });
                break;
            }
            result.left = result.right;
            currentLength -= patterns[result.right.id].length;
        }
        if (backward) {
            const temp = result.right;
            result.right = result.left;
            result.left = temp;
        }
        return result;
    }
    findAllNotIn(patterns, start_, length_) {
        let { start, length } = this.prepareFindParameters(start_, length_);
        const result = [];
        let patternFound = {
            left: {
                id: (-1),
                position: start
            },
            right: {
                id: (-1),
                position: start
            },
            value: new ByteStream()
        };
        do {
            const position = patternFound.right.position;
            patternFound = this.findFirstNotIn(patterns, patternFound.right.position, length);
            length -= (patternFound.right.position - position);
            result.push({
                left: {
                    id: patternFound.left.id,
                    position: patternFound.left.position
                },
                right: {
                    id: patternFound.right.id,
                    position: patternFound.right.position
                },
                value: patternFound.value
            });
        } while (patternFound.right.id != (-1));
        return result;
    }
    findFirstSequence(patterns, start_, length_, backward_) {
        let { start, length, backward } = this.prepareFindParameters(start_, length_, backward_);
        const firstIn = this.skipNotPatterns(patterns, start, length, backward);
        if (firstIn == (-1)) {
            return {
                position: (-1),
                value: new ByteStream()
            };
        }
        const firstNotIn = this.skipPatterns(patterns, firstIn, length - ((backward) ? (start - firstIn) : (firstIn - start)), backward);
        if (backward) {
            start = firstNotIn;
            length = (firstIn - firstNotIn);
        }
        else {
            start = firstIn;
            length = (firstNotIn - firstIn);
        }
        const value = new ByteStream({
            buffer: this._buffer.slice(start, start + length),
        });
        return {
            position: firstNotIn,
            value
        };
    }
    findAllSequences(patterns, start_, length_) {
        let { start, length } = this.prepareFindParameters(start_, length_);
        const result = [];
        let patternFound = {
            position: start,
            value: new ByteStream()
        };
        do {
            const position = patternFound.position;
            patternFound = this.findFirstSequence(patterns, patternFound.position, length);
            if (patternFound.position != (-1)) {
                length -= (patternFound.position - position);
                result.push({
                    position: patternFound.position,
                    value: patternFound.value,
                });
            }
        } while (patternFound.position != (-1));
        return result;
    }
    findPairedPatterns(leftPattern, rightPattern, start_, length_) {
        const result = [];
        if (leftPattern.isEqual(rightPattern))
            return result;
        const { start, length } = this.prepareFindParameters(start_, length_);
        let currentPositionLeft = 0;
        const leftPatterns = this.findAllPatternIn(leftPattern, start, length);
        if (!Array.isArray(leftPatterns) || leftPatterns.length == 0) {
            return result;
        }
        const rightPatterns = this.findAllPatternIn(rightPattern, start, length);
        if (!Array.isArray(rightPatterns) || rightPatterns.length == 0) {
            return result;
        }
        while (currentPositionLeft < leftPatterns.length) {
            if (rightPatterns.length == 0) {
                break;
            }
            if (leftPatterns[0] == rightPatterns[0]) {
                result.push({
                    left: leftPatterns[0],
                    right: rightPatterns[0]
                });
                leftPatterns.splice(0, 1);
                rightPatterns.splice(0, 1);
                continue;
            }
            if (leftPatterns[currentPositionLeft] > rightPatterns[0]) {
                break;
            }
            while (leftPatterns[currentPositionLeft] < rightPatterns[0]) {
                currentPositionLeft++;
                if (currentPositionLeft >= leftPatterns.length) {
                    break;
                }
            }
            result.push({
                left: leftPatterns[currentPositionLeft - 1],
                right: rightPatterns[0]
            });
            leftPatterns.splice(currentPositionLeft - 1, 1);
            rightPatterns.splice(0, 1);
            currentPositionLeft = 0;
        }
        result.sort((a, b) => (a.left - b.left));
        return result;
    }
    findPairedArrays(inputLeftPatterns, inputRightPatterns, start_, length_) {
        const { start, length } = this.prepareFindParameters(start_, length_);
        const result = [];
        let currentPositionLeft = 0;
        const leftPatterns = this.findAllIn(inputLeftPatterns, start, length);
        if (leftPatterns.length == 0)
            return result;
        const rightPatterns = this.findAllIn(inputRightPatterns, start, length);
        if (rightPatterns.length == 0)
            return result;
        while (currentPositionLeft < leftPatterns.length) {
            if (rightPatterns.length == 0) {
                break;
            }
            if (leftPatterns[0].position == rightPatterns[0].position) {
                result.push({
                    left: leftPatterns[0],
                    right: rightPatterns[0]
                });
                leftPatterns.splice(0, 1);
                rightPatterns.splice(0, 1);
                continue;
            }
            if (leftPatterns[currentPositionLeft].position > rightPatterns[0].position) {
                break;
            }
            while (leftPatterns[currentPositionLeft].position < rightPatterns[0].position) {
                currentPositionLeft++;
                if (currentPositionLeft >= leftPatterns.length) {
                    break;
                }
            }
            result.push({
                left: leftPatterns[currentPositionLeft - 1],
                right: rightPatterns[0]
            });
            leftPatterns.splice(currentPositionLeft - 1, 1);
            rightPatterns.splice(0, 1);
            currentPositionLeft = 0;
        }
        result.sort((a, b) => (a.left.position - b.left.position));
        return result;
    }
    replacePattern(searchPattern, replacePattern, start_, length_, findAllResult = null) {
        let result = [];
        let i;
        const output = {
            status: (-1),
            searchPatternPositions: [],
            replacePatternPositions: []
        };
        const { start, length } = this.prepareFindParameters(start_, length_);
        if (findAllResult == null) {
            result = this.findAllIn([searchPattern], start, length);
            if (result.length == 0) {
                return output;
            }
        }
        else {
            result = findAllResult;
        }
        output.searchPatternPositions.push(...Array.from(result, element => element.position));
        const patternDifference = searchPattern.length - replacePattern.length;
        const changedBuffer = new ArrayBuffer(this.view.length - (result.length * patternDifference));
        const changedView = new Uint8Array(changedBuffer);
        changedView.set(new Uint8Array(this.buffer, 0, start));
        for (i = 0; i < result.length; i++) {
            const currentPosition = (i == 0) ? start : result[i - 1].position;
            changedView.set(new Uint8Array(this.buffer, currentPosition, result[i].position - searchPattern.length - currentPosition), currentPosition - i * patternDifference);
            changedView.set(replacePattern.view, result[i].position - searchPattern.length - i * patternDifference);
            output.replacePatternPositions.push(result[i].position - searchPattern.length - i * patternDifference);
        }
        i--;
        changedView.set(new Uint8Array(this.buffer, result[i].position, this.length - result[i].position), result[i].position - searchPattern.length + replacePattern.length - i * patternDifference);
        this.buffer = changedBuffer;
        this.view = new Uint8Array(this.buffer);
        output.status = 1;
        return output;
    }
    skipPatterns(patterns, start_, length_, backward_) {
        const { start, length, backward } = this.prepareFindParameters(start_, length_, backward_);
        let result = start;
        for (let k = 0; k < patterns.length; k++) {
            const patternLength = patterns[k].length;
            const equalStart = (backward) ? (result - patternLength) : (result);
            let equal = true;
            for (let j = 0; j < patternLength; j++) {
                if (this.view[j + equalStart] != patterns[k].view[j]) {
                    equal = false;
                    break;
                }
            }
            if (equal) {
                k = (-1);
                if (backward) {
                    result -= patternLength;
                    if (result <= 0)
                        return result;
                }
                else {
                    result += patternLength;
                    if (result >= (start + length))
                        return result;
                }
            }
        }
        return result;
    }
    skipNotPatterns(patterns, start_, length_, backward_) {
        const { start, length, backward } = this.prepareFindParameters(start_, length_, backward_);
        let result = (-1);
        for (let i = 0; i < length; i++) {
            for (let k = 0; k < patterns.length; k++) {
                const patternLength = patterns[k].length;
                const equalStart = (backward) ? (start - i - patternLength) : (start + i);
                let equal = true;
                for (let j = 0; j < patternLength; j++) {
                    if (this.view[j + equalStart] != patterns[k].view[j]) {
                        equal = false;
                        break;
                    }
                }
                if (equal) {
                    result = (backward) ? (start - i) : (start + i);
                    break;
                }
            }
            if (result != (-1)) {
                break;
            }
        }
        return result;
    }
    prepareFindParameters(start = null, length = null, backward = false) {
        if (start === null) {
            start = (backward) ? this.length : 0;
        }
        if (start > this.length) {
            start = this.length;
        }
        if (backward) {
            if (length === null) {
                length = start;
            }
            if (length > start) {
                length = start;
            }
        }
        else {
            if (length === null) {
                length = this.length - start;
            }
            if (length > (this.length - start)) {
                length = this.length - start;
            }
        }
        return { start, length, backward };
    }
}
exports.ByteStream = ByteStream;
