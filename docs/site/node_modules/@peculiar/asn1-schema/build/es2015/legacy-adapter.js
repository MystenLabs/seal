import { AsnSerializer, AsnParser } from "@peculiar/asn1-codec";
import * as asn1js from "asn1js";
export function asnNodeToLegacyType(node) {
    if (node.ctx && node.start !== undefined && node.end !== undefined) {
        const contextData = node.ctx.data.slice(node.start, node.end);
        const parsed = asn1js.fromBER(contextData.buffer);
        if (parsed.offset === -1) {
            throw new Error("Error parsing ASN.1 with asn1js: " + parsed.result.error);
        }
        return parsed.result;
    }
    const derBytes = AsnSerializer.nodeToBytes(node);
    const parsed = asn1js.fromBER(derBytes.buffer);
    if (parsed.offset === -1) {
        throw new Error("Error parsing ASN.1 with asn1js: " + parsed.result.error);
    }
    return parsed.result;
}
function legacyTypeToAsnNode(value) {
    const derBytes = value.toBER();
    const parseResult = AsnParser.parse(new Uint8Array(derBytes), { captureRaw: true });
    if (parseResult.errors?.length) {
        throw new Error(`Failed to parse serialized ASN.1: ${parseResult.errors[0].message}`);
    }
    return parseResult.root;
}
export function createLegacyConverterAdapter(legacyConverter) {
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
