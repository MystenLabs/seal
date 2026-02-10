import { __decorate } from "tslib";
import { AsnConstructedOctetStringConverter, AsnProp, AsnPropTypes, AsnType, AsnTypeTypes, OctetString, } from "@peculiar/asn1-schema";
import { ContentEncryptionAlgorithmIdentifier } from "./types";
let EncryptedContent = class EncryptedContent {
    constructor(params = {}) {
        Object.assign(this, params);
    }
};
__decorate([
    AsnProp({ type: OctetString, context: 0, implicit: true, optional: true })
], EncryptedContent.prototype, "value", void 0);
__decorate([
    AsnProp({
        type: OctetString,
        converter: AsnConstructedOctetStringConverter,
        context: 0,
        implicit: true,
        optional: true,
        repeated: "sequence",
    })
], EncryptedContent.prototype, "constructedValue", void 0);
EncryptedContent = __decorate([
    AsnType({ type: AsnTypeTypes.Choice })
], EncryptedContent);
export { EncryptedContent };
export class EncryptedContentInfo {
    constructor(params = {}) {
        this.contentType = "";
        this.contentEncryptionAlgorithm = new ContentEncryptionAlgorithmIdentifier();
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AsnPropTypes.ObjectIdentifier })
], EncryptedContentInfo.prototype, "contentType", void 0);
__decorate([
    AsnProp({ type: ContentEncryptionAlgorithmIdentifier })
], EncryptedContentInfo.prototype, "contentEncryptionAlgorithm", void 0);
__decorate([
    AsnProp({ type: EncryptedContent, optional: true })
], EncryptedContentInfo.prototype, "encryptedContent", void 0);
