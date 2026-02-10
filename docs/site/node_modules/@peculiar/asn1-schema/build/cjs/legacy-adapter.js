"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.asnNodeToLegacyType = asnNodeToLegacyType;
exports.createLegacyConverterAdapter = createLegacyConverterAdapter;
const asn1_codec_1 = require("@peculiar/asn1-codec");
const asn1js = require("asn1js");
function asnNodeToLegacyType(node) {
    if (node.ctx && node.start !== undefined && node.end !== undefined) {
        const contextData = node.ctx.data.slice(node.start, node.end);
        const parsed = asn1js.fromBER(contextData.buffer);
        if (parsed.offset === -1) {
            throw new Error("Error parsing ASN.1 with asn1js: " + parsed.result.error);
        }
        return parsed.result;
    }
    const derBytes = asn1_codec_1.AsnSerializer.nodeToBytes(node);
    const parsed = asn1js.fromBER(derBytes.buffer);
    if (parsed.offset === -1) {
        throw new Error("Error parsing ASN.1 with asn1js: " + parsed.result.error);
    }
    return parsed.result;
}
function legacyTypeToAsnNode(value) {
    const derBytes = value.toBER();
    const parseResult = asn1_codec_1.AsnParser.parse(new Uint8Array(derBytes), { captureRaw: true });
    if (parseResult.errors?.length) {
        throw new Error(`Failed to parse serialized ASN.1: ${parseResult.errors[0].message}`);
    }
    return parseResult.root;
}
function createLegacyConverterAdapter(legacyConverter) {
    return {
        fromASN: (value) => {
            const legacyValue = asnNodeToLegacyType(value);
            return legacyConverter.fromASN(legacyValue);
        },
        toASN: (value) => {
            const legacyResult = legacyConverter.toASN(value);
            return legacyTypeToAsnNode(legacyResult);
        },
    };
}
