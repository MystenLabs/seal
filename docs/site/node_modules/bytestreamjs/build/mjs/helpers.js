export function parseByteMap(stream, map, elements, start = null, length = null) {
    if (start === null) {
        start = 0;
    }
    if (start > (stream.length - 1)) {
        return [];
    }
    if (length === null) {
        length = stream.length - start;
    }
    if (length > (stream.length - start)) {
        length = stream.length - start;
    }
    let dataView;
    if ((start == 0) && (length == stream.length)) {
        dataView = stream.view;
    }
    else {
        dataView = new Uint8Array(stream.buffer, start, length);
    }
    const resultArray = new Array(elements);
    let elementsCount = 0;
    let count = 0;
    const mapLength = map.length;
    while (count < length) {
        let structureLength = 0;
        resultArray[elementsCount] = {};
        for (let i = 0; i < mapLength; i++) {
            if (map[i].maxlength == 0) {
                if ("defaultValue" in map[i]) {
                    (resultArray[elementsCount])[map[i].name] = map[i].defaultValue;
                }
                continue;
            }
            const array = new Uint8Array(map[i].maxlength);
            for (let j = 0; j < map[i].maxlength; j++) {
                array[j] = dataView[count++];
            }
            const result = (map[i].func)(array);
            if (result.status == (-1)) {
                if (resultArray.length == 1) {
                    return [];
                }
                return resultArray.slice(0, resultArray.length - 1);
            }
            if (map[i].type != "check") {
                (resultArray[elementsCount])[map[i].name] = result.value;
            }
            count -= (map[i].maxlength - result.length);
            structureLength += result.length;
        }
        (resultArray[elementsCount++]).structureLength = structureLength;
    }
    return resultArray;
}
